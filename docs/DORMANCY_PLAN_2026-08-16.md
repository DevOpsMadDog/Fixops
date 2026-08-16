# Dormancy Plan — the 368 orphaned API prefixes

> Measured 2026-08-16 against the running container. An **orphan** is an
> `/api/v1/*` router prefix with **no callsite anywhere in the UI source**.

## The numbers

| Metric | Value |
|---|---|
| Backend router prefixes | **744** |
| Referenced by the UI | 376 |
| **Orphaned (no UI consumer)** | **368 (49%)** |
| Engines | 464 (457 imported by some router) |
| Python source | ~1.04M LOC |

## What the orphans actually are (sampled live, not assumed)

They are **not broken and not fake** — they answer honestly, they are simply
unused and unreachable from the product:

- `GET /api/v1/abuseipdb/` -> `{"service":"AbuseIPDB", "endpoints":[...], "api_key_present":false}`
- `GET /api/v1/akamai/`, `/apigee/`, `/amazon-inspector/` -> same shape: a connector
  descriptor with **no credentials configured**
- `GET /api/v1/anomaly-ml/groups` -> `{"group_count":0}` · `/ai-governance/models` -> `[]`
- `GET /api/v1/api-fuzzer/health`, `/algorithms/health` -> healthy engines with no data

So the pattern is: **built, wired, honest — and connected to nothing.**

## Categories

| Category | Count | Recommendation |
|---|---|---|
| Vendor integrations (needs customer creds) | 68 | **KEEP, mark opt-in** — real value once a customer connects their stack; gate behind connector config |
| Engine/domain endpoints (no UI, no data) | 290 | **DORMANT** — unmount from the default app; keep the code (sunk cost), stop maintaining/testing |
| Platform/admin | 10 | **KEEP** — operational surface |

## Why this is the right cut

Deleting is not required and not advised: the code is paid for and some of it becomes
valuable the moment a customer connects a tool. What costs us today is that all of it is
**mounted, advertised, tested and maintained** while serving no user:

- it inflates the API surface (8,346 route entries) and the boot path,
- it widens the attack surface (every mounted route is reachable),
- it makes the product read as unfocused to a buyer,
- it dilutes the test signal.

`FIXOPS_CORE_MODE=1` already solves the *presentation* half (API advertises 454 of 6,564
paths; the UI shows a curated 5-section nav). Dormancy is the *runtime* half.

## Execution order (safe)

1. **Make core mode the default** for demos/pilots — zero code risk, immediate effect.
2. **Gate the 68 vendor integrations** behind configured credentials — they already report
   `api_key_present:false`, so mount them only when a connector is configured.
3. **Unmount the ~290 engine-domain orphans** in batches, verifying after each:
   app boots, route-count drops by the expected delta, UAT 11/11, gates green.
4. Re-mount anything a real customer asks for — the code never left the repo.

## Full orphan list by category

### Vendor integrations — KEEP (gate behind creds) (68)

```
/api/v1/abuseipdb
/api/v1/akamai
/api/v1/akto
/api/v1/amazon-inspector
/api/v1/ansible-tower
/api/v1/apicrunch
/api/v1/apigee
/api/v1/auth0
/api/v1/aws-ecr
/api/v1/aws-eks
/api/v1/aws-iam
/api/v1/aws-redshift
/api/v1/aws-s3
/api/v1/aws-securityhub
/api/v1/aws-waf
/api/v1/azure-keyvault
/api/v1/azure-sentinel
/api/v1/bitbucket
/api/v1/blackduck
/api/v1/checkmarx
/api/v1/circleci
/api/v1/cloudflare
/api/v1/cyberark-pam
/api/v1/datadog-security
/api/v1/elastic-security
/api/v1/gcp-gke
/api/v1/gcp-scc
/api/v1/github
/api/v1/github-api
/api/v1/gitlab-pipeline
/api/v1/greynoise
/api/v1/hashicorp-vault
/api/v1/jenkins
/api/v1/jira-cloud
/api/v1/jira-sync
/api/v1/lacework
/api/v1/microsoft-purview
/api/v1/microsoft-teams
/api/v1/mimecast
/api/v1/mongodb-atlas
/api/v1/netskope
/api/v1/newrelic
/api/v1/nuclei
/api/v1/okta
/api/v1/pagerduty
/api/v1/pagerduty-events
/api/v1/prisma
/api/v1/proofpoint-tap
/api/v1/qualys
/api/v1/sentinelone
/api/v1/servicenow-sync
/api/v1/shodan
/api/v1/slack
/api/v1/slack-chatops
/api/v1/snowflake
/api/v1/snyk
/api/v1/sonarqube
/api/v1/splunk
/api/v1/splunk-soar-rest
/api/v1/sumologic
/api/v1/tanium
/api/v1/tenable-io
/api/v1/terraform-cloud
/api/v1/trivy
/api/v1/veracode
/api/v1/virustotal
/api/v1/wiz
/api/v1/zscaler-zia
```

### Engine/domain — DORMANT candidates (290)

```
/api/v1/access-control
/api/v1/access-governance
/api/v1/activity
/api/v1/ai-agent
/api/v1/ai-governance
/api/v1/ai-orchestrator
/api/v1/ai-scan
/api/v1/alert-mgmt
/api/v1/alerting
/api/v1/algorithms
/api/v1/anomalies
/api/v1/anomaly-ml
/api/v1/anti-phishing
/api/v1/api-abuse
/api/v1/api-analytics
/api/v1/api-fuzzer
/api/v1/api-gateway-security
/api/v1/appsec
/api/v1/argocd
/api/v1/asset-lifecycle
/api/v1/attack-simulation
/api/v1/attack-surface-mgmt
/api/v1/auto-evidence
/api/v1/auto-pentest
/api/v1/autonomous-remediation
/api/v1/backup-dr
/api/v1/backups
/api/v1/bandit
/api/v1/bandwidth-analysis
/api/v1/benchmarking
/api/v1/bigquery
/api/v1/blast-radius
/api/v1/bounty
/api/v1/braintrust
/api/v1/breach-detection
/api/v1/breach-sim
/api/v1/cache
/api/v1/casb
/api/v1/censys
/api/v1/change-tracker
/api/v1/checkov
/api/v1/choke-point
/api/v1/cicd
/api/v1/ciem
/api/v1/ciem-ad
/api/v1/classification
/api/v1/closed-loop
/api/v1/cloud-connectors
/api/v1/cloud-cost
/api/v1/cloud-governance
/api/v1/cloud-graph
/api/v1/cloud-native
/api/v1/cloud-security-engine
/api/v1/cnapp
/api/v1/code-to-cloud
/api/v1/compliance-dashboard
/api/v1/compliance-planner
/api/v1/compliance-reports
/api/v1/compliance-seed
/api/v1/composite-alerts
/api/v1/context-engine
/api/v1/contrast
/api/v1/correlations
/api/v1/council
/api/v1/council-enhanced
/api/v1/crossplane
/api/v1/cvss-reconciliation
/api/v1/dashboards
/api/v1/data
/api/v1/data-fabric
/api/v1/data-lake-security
/api/v1/data-privacy
/api/v1/data-residency
/api/v1/data-retention
/api/v1/databricks
/api/v1/db-security
/api/v1/dbir
/api/v1/ddos-protection
/api/v1/defender-xdr
/api/v1/dep-scanner
/api/v1/deploy
/api/v1/deploy-patterns
/api/v1/deployment
/api/v1/design-context
/api/v1/design-doc
/api/v1/dev-identity
/api/v1/developer
/api/v1/developer-profiles
/api/v1/discord
/api/v1/docs
/api/v1/drata
/api/v1/drift
/api/v1/drp
/api/v1/dtrack
/api/v1/duckdb-analytics
/api/v1/duo
/api/v1/elasticsearch
/api/v1/email-security
/api/v1/endpoint-security
/api/v1/event-bus
/api/v1/event-correlation
/api/v1/evidence-chain
/api/v1/evidence-collector
/api/v1/exceptions
/api/v1/executive
/api/v1/export
/api/v1/export-coverage
/api/v1/falcon
/api/v1/fastly
/api/v1/feature-flags
/api/v1/fedramp
/api/v1/firewall
/api/v1/firewall-mgmt
/api/v1/fix-engine
/api/v1/forensics-readiness
/api/v1/formula
/api/v1/gar
/api/v1/gate
/api/v1/gateway
/api/v1/ghsa
/api/v1/gitleaks
/api/v1/google-chat
/api/v1/graphql
/api/v1/graphrag
/api/v1/grype
/api/v1/guardrails
/api/v1/harbor
/api/v1/harness
/api/v1/helicone
/api/v1/hooks-yaml
/api/v1/hunt
/api/v1/identity
/api/v1/ids-ips
/api/v1/iga
/api/v1/imperva
/api/v1/ingest
/api/v1/intelligent-security
/api/v1/iot-security
/api/v1/jupiterone
/api/v1/k8s
/api/v1/kb
/api/v1/kong
/api/v1/kpi-tracking
/api/v1/kube-bench
/api/v1/langsmith
/api/v1/llm-firewall
/api/v1/llm-guard
/api/v1/llm-loop
/api/v1/llm-monitor
/api/v1/log-management
/api/v1/logs
/api/v1/loki
/api/v1/malicious-pkg
/api/v1/malware
/api/v1/mattermost
/api/v1/mcp-gateway
/api/v1/micro-pentest
/api/v1/misp
/api/v1/mitre-attack
/api/v1/mlops
/api/v1/mobile-security
/api/v1/multi-csp
/api/v1/my-feature
/api/v1/n8n
/api/v1/n8n-mgmt
/api/v1/nac
/api/v1/nl-graph
/api/v1/noname
/api/v1/notifications
/api/v1/oauth2
/api/v1/observability
/api/v1/offline-feed
/api/v1/onboarding
/api/v1/openclaw
/api/v1/opencti
/api/v1/opensearch
/api/v1/osv
/api/v1/otx
/api/v1/ownership
/api/v1/pam
/api/v1/patch-automation
/api/v1/patches
/api/v1/peer-insights
/api/v1/pentest
/api/v1/phishtank
/api/v1/physical-security
/api/v1/policy-engine
/api/v1/policy-generator
/api/v1/posture
/api/v1/posture-benchmark
/api/v1/posture-reports
/api/v1/pr-gate
/api/v1/prioritize
/api/v1/privilege-escalation-detector
/api/v1/prometheus
/api/v1/pulumi
/api/v1/purple-team
/api/v1/pyrit
/api/v1/questionnaires
/api/v1/raas-intel
/api/v1/rasp
/api/v1/rate-limits
/api/v1/rbac
/api/v1/regulatory-reporting
/api/v1/regulatory-tracker
/api/v1/rekor
/api/v1/remediation-board
/api/v1/report-builder
/api/v1/retention
/api/v1/risks
/api/v1/sailpoint-iga
/api/v1/salt-security
/api/v1/sbom-reeval
/api/v1/scanner-registry
/api/v1/scanners
/api/v1/scif
/api/v1/scorecard
/api/v1/secrets-manager
/api/v1/secrets-scanner
/api/v1/security
/api/v1/security-playbooks
/api/v1/security-posture-pdf
/api/v1/security-roi
/api/v1/security-scoreboard
/api/v1/security-scorecard
/api/v1/self-scan
/api/v1/semantic
/api/v1/semgrep
/api/v1/service-catalog
/api/v1/sessions
/api/v1/sigmahq
/api/v1/sla-engine
/api/v1/sla-escalation
/api/v1/sla-management
/api/v1/smart-dedup
/api/v1/soc
/api/v1/soc-automation
/api/v1/soc-workflow
/api/v1/spamhaus
/api/v1/stage-matrix
/api/v1/stream-v2
/api/v1/subsidiary
/api/v1/supply-chain-monitoring
/api/v1/syft
/api/v1/tags
/api/v1/teammates
/api/v1/tfsec
/api/v1/thousandeyes
/api/v1/threat-hunt
/api/v1/threat-intel-fusion
/api/v1/threat-model
/api/v1/threat-model-gen
/api/v1/threat-models
/api/v1/threat-simulation
/api/v1/tool-inventory
/api/v1/tool-overlap
/api/v1/tor-exit
/api/v1/toxic-combo
/api/v1/tprm-exchange
/api/v1/traceable
/api/v1/training
/api/v1/triage
/api/v1/trust
/api/v1/unified-dashboard
/api/v1/urlhaus
/api/v1/validate
/api/v1/vanta
/api/v1/veeam
/api/v1/vendor-compliance
/api/v1/verification
/api/v1/verify
/api/v1/versions
/api/v1/vllm
/api/v1/vuln
/api/v1/vuln-exceptions
/api/v1/vuln-intel-fusion
/api/v1/vuln-remediation
/api/v1/vuln-risk
/api/v1/vuln-scanner
/api/v1/waf
/api/v1/waf-engine
/api/v1/webhook-filter-rules
/api/v1/webhook-subscriptions
/api/v1/wireless-security
/api/v1/workday
/api/v1/xsoar
/api/v1/zap
/api/v1/zero-gravity
/api/v1/zero-trust
/api/v1/zero-trust-legacy
```

### Platform/admin — KEEP (10)

```
/api/v1/audit-analytics
/api/v1/audit-management
/api/v1/error-audit
/api/v1/license
/api/v1/license-scanner
/api/v1/licenses
/api/v1/metrics-dashboard
/api/v1/metrics-ts
/api/v1/security-metrics-collector
/api/v1/tenants
```
