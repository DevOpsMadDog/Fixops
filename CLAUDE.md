# ALDECI (Fixops) — Beast Mode v6 CTO Operating Manual

> **Branch**: `features/intermediate-stage` (NOT main)
> **Mode**: Beast Mode v6 — autonomous CTO mode

---

## YOU ARE THE CTO — NOT A CODER

You (Claude Code) are the CTO. You PLAN, REVIEW, and DELEGATE.
You do NOT write code yourself except for small config changes (<10 lines).

### How You Operate:

**If OMC is installed** (check: `which omc`):
- `/team "task description"` — delegates to cheaper models via OMC pipeline (PLAN → PRD → EXEC → VERIFY → FIX)
- `omc autoresearch "question"` — autonomous investigation
- `omc ask "quick question"` — routes to cheapest model

**If OMC is NOT installed** (fallback):
- Use Claude Code's built-in Task/Agent tool to spawn subagents for implementation
- You review what they produce, run tests, commit
- Still: delegate, don't write code yourself

**Token budget**: You are Opus ($15/M tokens). Haiku is $0.25/M. That's 60x. Delegate.

### Auto-Save Rule (CRITICAL):

**Every 15-20 minutes, you MUST save your work to git:**
```bash
git add -A && git commit -m "beast-mode(wip): [brief description of what changed]" && git push origin features/intermediate-stage
```
This is non-negotiable. Work that isn't committed doesn't exist. Set a mental timer.
If a task takes longer than 20 minutes, commit the partial progress anyway.

### Session Routine:

**Start:**
1. `git pull origin features/intermediate-stage`
2. `code-review-graph stats` — load codebase structure into context (46x cheaper than reading files)
3. Run Beast Mode tests only: `python -m pytest tests/test_phase*.py tests/test_connector_framework.py tests/test_trustgraph.py tests/test_pipeline_api.py tests/test_persona_workflows.py -x --tb=short --timeout=10 -q`
4. Read "What To Build Next" below
5. Delegate the highest priority task

**Every 15-20 minutes:**
- `git add -A && git commit -m "beast-mode(wip): progress on [task]" && git push origin features/intermediate-stage`

**End of session (Nightly Handoff to SwarmClaw):**
- Update "Recent Changes" at bottom of this file
- Queue remaining tasks to SwarmClaw for overnight agents (see SwarmClaw API below)
- Final commit: `beast-mode(status): summary of today's work + queued N tasks to SwarmClaw`

**Morning (Pull SwarmClaw overnight results):**
- Check what SwarmClaw agents did: `curl -s http://localhost:3456/api/tasks | python3 -m json.tool`
- Review any PRs agents created: `gh pr list --state open`
- Pull latest: `git pull origin features/intermediate-stage`
- Rebuild graph if stale: `code-review-graph build`

---

## YOU CONTROL SWARMCLAW (Orchestrator API)

SwarmClaw is your nighttime workforce. You (Claude Code) queue tasks, agents execute overnight.

### SwarmClaw API (http://localhost:3456):

**List agents:**
```bash
curl -s http://localhost:3456/api/agents | python3 -m json.tool
```

**Create a task for an agent:**
```bash
curl -s -X POST http://localhost:3456/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"title": "TASK TITLE", "agent_id": "AGENT_ID", "prompt": "Detailed instructions...", "status": "ready", "priority": "high"}'
```

**Check task status:**
```bash
curl -s http://localhost:3456/api/tasks | python3 -m json.tool
```

**Create a schedule:**
```bash
swarmclaw schedules create --base-url http://localhost:3456 \
  --name "Schedule Name" --agent-id AGENT_ID \
  --task-prompt "What to do" --schedule-type cron --cron "0 22 * * *"
```

**Check schedules:**
```bash
curl -s http://localhost:3456/api/schedules | python3 -m json.tool
```

### Model routing (all FREE via OpenRouter):
| Agent | Model | Use for |
|-------|-------|---------|
| Code Builder | `qwen/qwen3.6-plus:free` | Implementation, features, bug fixes |
| Test Writer | `qwen/qwen3.6-plus:free` | Unit, integration, e2e tests |
| Doc Generator | `gemma4` (local Ollama) | API docs, guides, changelogs |
| Security Reviewer | Council: Qwen 3.6+ + Kimi K2 | Vulnerability scanning, OWASP |
| Code Reviewer | Council: Qwen 3.6+ + Kimi K2 | Quality, patterns, best practices |

### Nightly handoff workflow:
1. At end of day, identify tasks you didn't finish
2. Queue each to SwarmClaw via API (use Code Builder agent for implementation tasks)
3. Agents pick up tasks, write code, commit to `features/intermediate-stage`
4. Morning: you review what they did, run tests, approve or fix

### Example — queue a task before signing off:
```bash
curl -s -X POST http://localhost:3456/api/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Add tests for brain_pipeline.py error handling",
    "prompt": "Write pytest tests covering all error paths in core/brain_pipeline.py. Use code-review-graph impact to find callers. Commit with beast-mode(nightly): prefix.",
    "status": "ready",
    "priority": "high"
  }'
```

---

## WHAT IS BEAST MODE v6

Beast Mode is NOT custom code. It's a configuration/integration layer that wires together 7 existing open-source tools to build ALDECI autonomously.

**Rule #1: Don't build what already exists.**

### The 8-Tool Stack:

| Tool | Purpose | Stars |
|------|---------|-------|
| **code-review-graph** | **AST codebase map — 46x token reduction. ALWAYS use before reading files.** | — |
| oh-my-claudecode (OMC) | 19 agents, team pipeline, autoresearch, smart routing | 15K+ |
| everything-claude-code | 156+ skills, 38 subagents, continuous learning | 140K+ |
| SwarmClaw | Kanban control plane, scheduling, agent lifecycle | 21K+ |
| TrustGraph (MCP) | Knowledge graph, GraphRAG, 5 Context Cores | — |
| OMNI | CLI token compression (90% reduction) | — |
| Context7 (MCP) | Live library documentation | — |
| Ollama | Local free models (Gemma 4) | — |

### code-review-graph — WHY IT'S TOOL #1:
- Parses entire codebase via Tree-sitter AST → SQLite graph (34,301 nodes, 216,476 edges for ALDECI)
- Graph DB lives at `.code-review-graph/graph.db` (169 MB)
- **BEFORE reading any file**, query the graph: `code-review-graph query "what calls brain_pipeline.py"`
- **For blast radius**: `code-review-graph impact "core/connectors.py"` → shows all affected files
- **For understanding structure**: `code-review-graph stats` → function count, class hierarchy, import map
- **Rebuilt nightly at 6am** via SwarmClaw schedule (after agents finish, before Opus review)
- Install: `pip install code-review-graph` → Build: `code-review-graph build` (runs in project root)

### Two Layers:

**Layer 1 — Claude Code Supercharged (Daytime):**
Claude Code + OMC + everything-claude-code + TrustGraph + OMNI + Context7.
You (CTO) review and approve. OMC agents do the coding.

**Layer 2 — SwarmClaw Autonomous (Nighttime, 10pm-8am):**
SwarmClaw + OpenClaw agents (Qwen 3.6 Plus, Kimi K2, Gemma 4 local) + Hermes.
Free models write code. Opus reviews via quality gate.

### Beast Mode Framework Repo:

Location: **`../best-mode-dev-framework/`** (sibling to this Fixops repo)
GitHub: `DevOpsMadDog/best-mode-dev-framework`

```
best-mode-dev-framework/
├── setup.sh                          # One-command installer for all 7 tools
├── layer1-claude-supercharged/       # OMC config, Claude settings, install script
├── layer2-swarmclaw-autonomous/      # Docker compose, agent YAMLs, schedules
│   ├── docker-compose.yml            # SwarmClaw + TrustGraph + Ollama + Redis + PostgreSQL
│   ├── agents/                       # code-builder, test-writer, doc-generator, security-reviewer, code-reviewer
│   └── schedules/                    # nightly-build (10pm), morning-review (7am), weekly-health (Sun 3am)
├── quality-gate/                     # Opus CTO review config, checklist, escalation rules
├── project-templates/                # python-fastapi, react-frontend, fullstack templates
├── examples/aldeci/                  # ALDECI-specific kanban seed, trustgraph cores, nightly priorities
└── docs/                             # architecture.md, daily-workflow.md
```

---

## WHAT IS ALDECI

ALDECI is an **ASPM + CTEM + CSPM platform** — a unified, self-hosted, AI-native security intelligence platform.
- Replaces $50K-500K/yr enterprise tools with $35-60/month self-hosted stack
- TrustGraph (5 Knowledge Cores) for versioned security knowledge
- Karpathy LLM Consensus (4 free models + Opus escalation) for decisions
- 28+ threat intelligence feeds, 32 scanner normalizers, 13 PULL + 7 bidirectional connectors
- 30 personas, 6 RBAC roles, 7 compliance frameworks
- Full architecture: `docs/ALDECI_REARCHITECTURE_v2.md`

---

## TESTING STRATEGY

There are ~327 test files. **Only run Beast Mode tests** for day-to-day work:

### Beast Mode Tests (run these — 709 tests passing):
```bash
python -m pytest \
  tests/test_phase2_connectors.py tests/test_phase3_llm_council.py \
  tests/test_phase4_integration.py tests/test_phase5_enterprise.py tests/test_phase6_streaming.py \
  tests/test_phase7_analytics.py tests/test_phase8_mcp.py tests/test_phase9_playbooks.py \
  tests/test_phase10_e2e.py tests/test_connector_framework.py tests/test_trustgraph.py \
  tests/test_pipeline_api.py tests/test_persona_workflows.py \
  -x --tb=short --timeout=10 -q -o "addopts="
```

### Legacy Tests (~190 files — DO NOT run routinely):
These test older modules (CLI, evidence, compliance, scanners, risk scoring, etc.).
Only run if you're modifying legacy code. They may have outdated assumptions.

### Full Suite (only for release validation):
```bash
python -m pytest tests/ --timeout=10 -x -q
```

---

## PROJECT STRUCTURE

```
.
├── suite-api/          # FastAPI gateway — 34 router mounts (22.6K LOC)
├── suite-core/         # Core engines — brain pipeline, connectors, CLI (140.1K LOC)
│   ├── core/           # Business logic
│   ├── connectors/     # New PullConnector framework
│   └── trustgraph/     # TrustGraph MCP server + KnowledgeStore
├── suite-attack/       # Offensive security — MPTE, attack sim (6.7K LOC)
├── suite-feeds/        # Threat intel feeds — 28+ sources (4.4K LOC)
├── suite-evidence-risk/# Evidence, risk scoring, compliance (20.3K LOC)
├── suite-integrations/ # External integrations — MCP, webhooks (6.8K LOC)
├── suite-ui/
│   ├── aldeci/         # Legacy React UI (FROZEN — do NOT modify)
│   └── aldeci-ui-new/  # Active UI (React 19 + Vite 6 + Tailwind v4)
├── tests/              # 327 test files (137 Beast Mode + 190 legacy)
├── docker/             # Docker + Kubernetes configs
├── docs/               # ALDECI_REARCHITECTURE_v2.md (source of truth)
├── sitecustomize.py    # Auto-injects suite paths into sys.path
└── requirements.txt
```

### Import Mechanism
`sitecustomize.py` auto-prepends all suite directories to `sys.path`:
```python
from core.brain_pipeline import BrainPipeline  # just works
```

---

## WHAT TO BUILD NEXT (Priority Order)

### HIGH PRIORITY
1. **Register API keys** — NVD (nvd.nist.gov) + abuse.ch (auth.abuse.ch) — reminder set for 2026-04-17 18:00. Wire OTX AlienVault + URLhaus once keys acquired.
2. **Scheduled report delivery** — email/Slack via n8n workflows now that N8nAPIClient is live
3. **OpenClaw pentest swarm** — autonomous red team via attack sim
4. **SBOM generation endpoint** — `/api/v1/sbom` export in CycloneDX/SPDX format
5. **Wire tests for awareness_score, ndr, xdr, edr engines** — engine files exist, test files have 0 tests

### MEDIUM PRIORITY
6. **Wire live threat intel keys** — AbuseIPDB (1k/day free), OTX AlienVault, URLhaus once registered
7. **n8n operational** — run `docker compose up` (n8n now in docker-compose.yml, port 5678)
8. **Zero Trust enforcement** — policy engine backend for /zero-trust UI page (ZeroTrustPolicyDashboard.tsx exists)

### LOWER PRIORITY
9. Connect 93 frontend pages to real backend data (most currently use mock/static data)
10. TrustGraph event bus — 97% of 3,036 endpoints still disconnected from TrustGraph knowledge graph

### DONE (sessions 2026-04-13 and 2026-04-14)
- ✅ Beast Mode test coverage +138 tests (brain_pipeline + 19 scanner normalizers) → 285 tests
- ✅ TrustGraph GraphRAG retriever (BFS traversal, semantic search, neighborhood) — 31 tests
- ✅ Error handling auditor (AST-based, 652 findings, fixed top 6 critical bare-except)
- ✅ SLA auto-escalation engine (tiered: notify/reassign/escalate) — 28 tests
- ✅ Vulnerability lifecycle tracker (8-state machine, metrics) — 61 tests
- ✅ Digital Risk Protection engine (typosquat, creds, certs, paste) — 23 tests
- ✅ Deception Engine (canary tokens, honeypots) — wired
- ✅ Frontend: Compliance Dashboard (/compliance) — 6 frameworks, evidence table, audit timeline
- ✅ Frontend: SOC T1 Dashboard already existed at /mission-control/soc-t1 — 1604 lines
- ✅ OpenAPI developer portal (spec export, Postman, endpoint explorer) — 34 tests
- ✅ CIEM engine (IAM entitlement, privilege escalation) — 35 tests
- ✅ Redis Queue (horizontal scaling, /api/v1/queue) — 25 tests
- ✅ SAML/OIDC SSO Bridge + PyJWKClient RS256 validation (no more verify_signature=False) — 70+68 tests
- ✅ Frontend: Threat Intel Dashboard (/threat-intel), Asset Inventory (/assets), Vuln Lifecycle (/vuln-lifecycle)
- ✅ GraphRAG wired to Copilot chat — 80 tests
- ✅ Attack Path Analysis (BFS lateral movement, /api/v1/attack-paths) — 23 tests
- ✅ Security Posture Advisor (/api/v1/posture-advisor) — 35 tests
- ✅ Insider Threat Detection (/api/v1/insider-threat) — 52 tests
- ✅ CVE Enrichment (NVD+EPSS+KEV, /api/v1/cve) — 37 tests
- ✅ Security KPI Tracker (MTTD/MTTR/scorecard, /api/v1/kpi) — 43 tests
- ✅ STRIDE Threat Modeling (/api/v1/threat-modeling) — 33 tests
- ✅ Vendor Risk Assessment (/api/v1/vendor-risk) — 25 tests
- ✅ Compliance Evidence Auto-Collector — 35 tests
- ✅ All new routers wired into app.py
- ✅ Multi-tenant isolation fixes — Redis queue org_id keys, attack_path guards, SSO bridge org_id column, insider threat resolve_alert guard (all 4 findings from b9d5aabe resolved)

### DONE (session 2026-04-16, Wave 9+10 — Autonomous parallel build)

**Wave 9 Backend Engines (all in suite-core/core/):**
- ✅ cyber_insurance_engine.py — CyberInsurance (policies_v2/claims_v2/coverage_gaps, tier assignment) — 30+ tests
- ✅ executive_reporting_engine.py — Executive Reporting (reports/KPIs/board decks) — 30+ tests
- ✅ cloud_compliance_engine.py — Cloud Compliance (CIS/NIST/SOC2/PCI-DSS, drift detection) — 40 tests
- ✅ endpoint_compliance_engine.py — Endpoint Compliance (severity-weighted scoring, bulk ingestion) — 38 tests
- ✅ api_security_mgmt_engine.py — API Security Mgmt (OWASP API Top 10, SHA-256 key hashing) — 34 tests
- ✅ vuln_intelligence_engine.py — Vulnerability Intelligence (CVE upserts, EPSS/KEV, advisories) — 38 tests
- ✅ password_policy_engine.py — Enhanced (MFA enrollment, password strength scoring, run_audit) — 52 tests
- ✅ security_training_engine.py — Enhanced (certificates, assignments, department compliance) — 45 tests
- ✅ threat_intel_platform_engine.py — TIP (IOC dedup, TLP reports, bulk ingest, relationship graph) — 34 tests
- ✅ attack_surface_engine.py — ASM (severity-weighted risk scoring, exposure lifecycle, change events) — 29 tests
- ✅ UBA, VulnScanner, VulnTrend test suites committed (engines existed, tests added)

**Wave 9 New Routers wired into app.py:**
- ✅ /api/v1/cloud-compliance, /api/v1/endpoint-compliance, /api/v1/exec-reporting
- ✅ /api/v1/api-security-engine, /api/v1/vuln-intel
- ✅ /api/v1/tip (ThreatIntelPlatform), /api/v1/asm (AttackSurface)

**Wave 9 New Frontend Pages:**
- ✅ /dlp — DLPDashboard (PII detection bars, SVG gauges, policy/incident feed)
- ✅ /secret-scanner — SecretScannerDashboard (scan jobs, findings with entropy, trigger form)
- ✅ /threat-intel-platform — ThreatIntelPlatformDashboard (TLP badges, IOC search, check form)
- ✅ /attack-surface-dashboard — AttackSurfaceDashboard (SVG surface score gauge, exposure feed)
- ✅ /cyber-insurance — CyberInsuranceDashboard (policies table, claims, coverage assessment)
- ✅ /executive-reporting — ExecutiveReportingDashboard (reports, KPIs, board presentations)
- ✅ /cloud-compliance — CloudComplianceDashboard (framework scores, failed controls, remediation)
- ✅ /endpoint-compliance — EndpointComplianceDashboard (OS distribution, department stacked bars)
- ✅ /api-security-mgmt — APISecurityMgmtDashboard (OWASP tracking, abuse events, scan results)
- ✅ /vuln-intelligence — VulnIntelligenceDashboard (CVE table with EPSS/KEV, advisor subscriptions)

**Wave 9 Mock→Live API wiring (30+ pages converted):**
- ✅ AwarenessScore, ConfigBenchmark, CCM, CVESearch, DataGovernance, DevSecOps, Regulatory, DLP
- ✅ AppSecurity, SecurityTraining, PasswordPolicy, CrossDomainAnalytics (DuckDB)
- ✅ VulnHeatmap, SecurityRoadmap, SLA, CMDB, SupplyChain
- ✅ DataClassification, DigitalForensics, SecurityAwareness (fixed wrong API paths)
- ✅ PentestManagement, RedTeam, BugBounty (confirmed already wired correctly)

**Bug fixes:**
- ✅ CyberInsuranceEngine._v2_initialized moved from class var to instance var (test isolation)
- ✅ SecurityAwareness page was hitting /api/v1/security-awareness (wrong) → /api/v1/awareness-score (fixed)

**Test totals:** 1,400+ tests across Beast Mode suite, zero regressions

---

### DONE (session 2026-04-16, Wave 11+12 — Autonomous parallel build)

**Wave 11 Backend Engines (all in suite-core/core/):**
- ✅ zero_trust_policy_engine.py — ZeroTrust policy eval, compliance posture, maturity score — 44 tests
- ✅ siem_integration_engine.py — SIEM event normalization, correlation, alert management — 38 tests
- ✅ nac_engine.py — NAC device enrollment, posture checks, policy enforcement — 47 tests
- ✅ waf_engine.py — WAF rules, virtual patches, rate limiting — 40 tests
- ✅ casb_engine.py — Shadow IT discovery, OAuth control, data activity — 43 tests
- ✅ mdm_engine.py — Device enrollment, compliance checks, remote wipe — 49 tests
- ✅ compliance_evidence_collector.py — Evidence requests, auto-collect, audit readiness — 41 tests
- ✅ mitre_attack_router.py — MITRE ATT&CK coverage dashboard — 14 tactics wired
- ✅ ciso_report_router.py — CISO executive report with export

**Wave 12 Backend Engines (all in suite-core/core/):**
- ✅ network_monitoring_engine.py — Traffic sampling, alert rules, interface monitoring — 30 tests
- ✅ bandwidth_analysis_engine.py — QoS policies, anomaly detection (z-score), utilization trends — 33 tests
- ✅ service_account_auditor_engine.py — IAM audit, unused/overprivileged detection, rotation — 41 tests
- ✅ privilege_escalation_detector_engine.py — Anomaly scoring, detection rules, heatmap — 48 tests
- ✅ container_registry_security_engine.py — Image scanning, policy evaluation, severity counts — 33 tests
- ✅ software_composition_analysis_engine.py — SCA, Log4Shell/CVE detection, license risk — 30 tests
- ✅ security_automation_engine.py — Automation rules, execution history, success rate — 32 tests
- ✅ incident_orchestration_engine.py — 5-state lifecycle, timeline, MTTR metrics — 39 tests
- ✅ threat_geolocation_engine.py — Impossible travel detection, country heatmap, geo-blocking — 43 tests
- ✅ ip_reputation_engine.py — Bulk scoring, blocklist, category-based risk — 42 tests
- ✅ firewall_policy_engine.py — Rule conflict detection, coverage gaps, shadow rules — 31 tests
- ✅ network_segmentation_engine.py — Lateral movement risk, segmentation score, flow policies — 34 tests
- ✅ crypto_key_management_engine.py — Key rotation, expiry tracking, audit log — 34 tests
- ✅ certificate_lifecycle_engine.py — Cert status, renewal history, expiry alerts — 34 tests
- ✅ kubernetes_security_engine.py — Cluster findings, CIS benchmarks, RBAC analysis — 57 tests
- ✅ cloud_native_security_engine.py — Cloud misconfigs, posture checks — 56 tests
- ✅ passive_dns_engine.py — Passive DNS records, domain tracking — tests wired
- ✅ iam_policy_analyzer.py — Wildcard/toxic combo detection, risk scoring — 40 tests
- ✅ cloud_drift_engine.py — IaC baseline drift, acknowledge/remediate lifecycle — 34 tests
- ✅ data_retention_engine.py — GDPR/CCPA policy lifecycle, deletion audit — 28 tests
- ✅ evidence_chain_engine.py — Tamper-evident custody chain, sealed guard — 30 tests

**Wave 12 New Routers wired into app.py:**
- ✅ /api/v1/network-monitoring, /api/v1/bandwidth-analysis
- ✅ /api/v1/service-account-auditor, /api/v1/privilege-escalation
- ✅ /api/v1/threat-geolocation, /api/v1/ip-reputation
- ✅ /api/v1/security-automation, /api/v1/incident-orchestration
- ✅ /api/v1/firewall-policy, /api/v1/network-segmentation
- ✅ /api/v1/crypto-keys, /api/v1/certificates
- ✅ /api/v1/kubernetes-security, /api/v1/cloud-native
- ✅ /api/v1/passive-dns, /api/v1/iam-policy, /api/v1/cloud-drift
- ✅ /api/v1/data-retention, /api/v1/evidence-chain
- ✅ /api/v1/container-registry-security, /api/v1/sca

**Wave 12 New Frontend Pages:**
- ✅ /container-registry — ContainerRegistryDashboard
- ✅ /network-monitoring — NetworkMonitoringDashboard
- ✅ /sca — SCADashboard (Software Composition Analysis)
- ✅ /service-account-audit — ServiceAccountAuditDashboard
- ✅ /firewall-policy — FirewallPolicyDashboard
- ✅ /network-segmentation — NetworkSegmentationDashboard
- ✅ /threat-geolocation — ThreatGeolocationDashboard (in progress)
- ✅ /ip-reputation — IPReputationDashboard (in progress)

**Test totals:** 1,400 base + 600+ Wave 12 = 2,000+ tests, zero regressions

---

### DONE (session 2026-04-16, Wave 13+14 — Autonomous parallel build)

**Wave 13 Backend Engines (all in suite-core/core/):**
- ✅ secrets_management_engine.py — SecretsManagement (store/rotate/revoke/expiry, NIST SP 800-57) — 29 tests
- ✅ vulnerability_remediation_engine.py — VulnRemediation (8-state lifecycle, SLA, metrics) — tests
- ✅ ddos_protection_engine.py — DDoSProtection (rate limiting, pattern detection, mitigation) — tests
- ✅ api_gateway_security_engine.py — APIGatewaySecurity (OWASP, key hashing, rate limits) — tests
- ✅ alerting_notification_engine.py — AlertingNotification (policies, MTTR, ack/resolve) — 35 tests
- ✅ risk_aggregator_engine.py — RiskAggregator (entity scoring, heatmap, org composite A-F grade) — 39 tests
- ✅ security_event_correlation_engine.py — SecurityEventCorrelation (time-windowed pattern matching) — 31 tests
- ✅ threat_intel_fusion_engine.py — ThreatIntelFusion (consensus confidence, TLP, IOC lifecycle) — 32 tests
- ✅ cloud_cost_security_engine.py — CloudCostSecurity (anomaly detection >50% MoM spike) — 60 tests
- ✅ data_lake_security_engine.py — DataLakeSecurity (assessment scoring, exfiltration risk) — 32 tests

**Wave 13 Routers wired into app.py:**
- ✅ /api/v1/secrets-management, /api/v1/vuln-remediation, /api/v1/ddos-protection, /api/v1/api-gateway-security
- ✅ /api/v1/alerting, /api/v1/risk-aggregator, /api/v1/event-correlation, /api/v1/threat-intel-fusion
- ✅ /api/v1/cloud-cost, /api/v1/data-lake-security

**Wave 14 Backend Engines (all in suite-core/core/):**
- ✅ mobile_device_management_engine.py — MDM (enroll/compliance/wipe, platform isolation) — 35 tests
- ✅ ot_security_engine.py — OTSecurity/ICS/SCADA (asset lifecycle, anomaly detection) — 38 tests
- ✅ data_privacy_engine.py — DataPrivacy (DSR requests, 30-day overdue detection) — 30 tests
- ✅ gdpr_compliance_engine.py — GDPRCompliance (6 lawful bases, consent lifecycle, GDPR score) — 29 tests
- ✅ physical_security_engine.py — PhysicalSecurity (locations, access events, incidents) — 38 tests
- ✅ access_control_engine.py — AccessControl (RBAC policies, grants, check_access JOIN) — 37 tests
- ✅ siem_integration_engine.py — SIEMIntegration (sources, events, correlation alerts) — 38 tests
- ✅ log_management_engine.py — LogManagement (retention policy enforcement, LIKE search) — 35 tests
- ✅ wireless_security_engine.py — WirelessSecurity (AP security, rogue AP detection) — 53 tests
- ✅ network_access_control_engine.py — NAC (5-check posture scoring, quarantine logic) — 44 tests

**Wave 14 Routers wired into app.py:**
- ✅ /api/v1/mdm, /api/v1/ot-security, /api/v1/data-privacy, /api/v1/gdpr
- ✅ /api/v1/physical-security, /api/v1/access-control, /api/v1/siem, /api/v1/log-management
- ✅ /api/v1/wireless-security, /api/v1/nac

**Test totals:** 2,000 base + 387 Wave 14 = 2,400+ tests, 263 core Beast Mode tests passing, zero regressions

---

### DONE (session 2026-04-16, Wave 15+16 — Autonomous parallel build)

**Wave 15 Backend Engines (all in suite-core/core/):**
- ✅ email_filtering_engine.py — EmailFiltering (allow/block lists, quarantine) — tests
- ✅ anti_phishing_engine.py — AntiPhishing (URL analysis, domain spoofing detection) — tests
- ✅ soc_workflow_engine.py — SOCWorkflow (case management, SLA tracking) — tests
- ✅ incident_triage_engine.py — IncidentTriage (AI-assisted severity scoring) — tests
- ✅ threat_simulation_engine.py — ThreatSimulation (red/blue team exercise orchestration) — tests
- ✅ security_scoreboard_engine.py — SecurityScoreboard (team/dept gamification) — tests
- ✅ asset_lifecycle_engine.py — AssetLifecycle (procurement→decommission, EOL alerts) — tests
- ✅ vuln_exception_engine.py — VulnException (risk acceptance workflow, expiry tracking) — tests
- ✅ breach_detection_engine.py — BreachDetection (behavioral anomalies, IoC correlation) — tests
- ✅ forensics_readiness_engine.py — ForensicsReadiness (evidence collection readiness scoring) — tests
- ✅ regulatory_reporting_engine.py — RegulatoryReporting (multi-framework report generation) — tests
- ✅ audit_management_engine.py — AuditManagement (audit scheduling, finding lifecycle) — tests

**Wave 15 Routers wired:** /api/v1/email-filtering, /api/v1/anti-phishing, /api/v1/soc-workflow,
/api/v1/incident-triage, /api/v1/threat-simulation, /api/v1/security-scoreboard,
/api/v1/asset-lifecycle, /api/v1/vuln-exception, /api/v1/breach-detection,
/api/v1/forensics-readiness, /api/v1/regulatory-reporting, /api/v1/audit-management

**Wave 16 Backend Engines (all in suite-core/core/):**
- ✅ supply_chain_monitoring_engine.py — SupplyChainMonitoring (supplier risk, events) — 32 tests
- ✅ vendor_compliance_engine.py — VendorCompliance (6-item compliance check, requirements) — 34 tests
- ✅ cloud_governance_engine.py — CloudGovernance (policy violations, compliance score) — 40 tests
- ✅ policy_enforcement_engine.py — PolicyEnforcement (versioning, exception lifecycle) — 38 tests
- ✅ security_metrics_dashboard_engine.py — MetricsDashboard (dashboards, widgets, snapshots) — 34 tests
- ✅ kpi_tracking_engine.py — KPITracking (higher/lower direction, achievement %, trend) — 47 tests

**Wave 16 Routers wired:** /api/v1/supply-chain-monitoring, /api/v1/vendor-compliance,
/api/v1/cloud-governance, /api/v1/policy-enforcement, /api/v1/metrics-dashboard, /api/v1/kpi-tracking

**Test totals after Wave 16:** 2,400+ base + ~500 Wave 15-16 = 2,900+ tests, zero regressions

---

### DONE (session 2026-04-16, Wave 17+18 — Autonomous parallel build)

**Wave 17 Tests for engines without coverage:**
- ✅ test_insider_threat_engine.py — 36 tests (analyze_user_risk, anomaly detection, alert lifecycle)
- ✅ test_intelligent_security_engine.py — 34 tests (MindsDB safety helpers, ThreatIntelligence, AttackPlan)
- ✅ test_mitre_attack_coverage_engine.py — 48 tests (seed, add_technique, get_coverage, heatmap, gaps)
- ✅ test_security_playbook_engine.py — 32 tests (execute_playbook simulation, org isolation)

**Wave 17 New Backend Engines:**
- ✅ mfa_management_engine.py — MFAManagement (totp/sms/email/hardware_key/push, enrollment lifecycle) — 35 tests
- ✅ threat_score_engine.py — ThreatScore (weighted signal aggregation, risk_level mapping) — 33 tests
- ✅ security_budget_engine.py — SecurityBudget (allocations, spend tracking, ROI assessment) — 44 tests
- ✅ compliance_gap_engine.py — ComplianceGap (control gaps, remediation plans, compliance %) — 35 tests

**Wave 17 Routers wired:** /api/v1/mfa, /api/v1/threat-scores, /api/v1/security-budget, /api/v1/compliance-gaps

**Wave 18 New Backend Engines (in progress):**
- ✅ ai_governance_engine.py — AIGovernance (model lifecycle, bias/security assessments, incidents) — 35 tests
- ✅ digital_identity_engine.py — DigitalIdentity (IAL1/2/3, NIST 800-63, verification events) — 35 tests
- ✅ attack_chain_engine.py — AttackChain (kill chain phases, multi-step lateral movement) — 35 tests
- ✅ threat_exposure_engine.py — ThreatExposure (signal correlation, exposure scoring 0-100) — 35 tests
- ✅ software_license_security_engine.py — SoftwareLicenseSecurity (OSS risk, violations) — 35 tests
- ✅ cloud_identity_engine.py — CloudIdentity (IAM, federated access, permission analysis) — 35 tests

**Wave 18 Routers wired:** /api/v1/ai-governance, /api/v1/digital-identity, /api/v1/attack-chains,
/api/v1/threat-exposure, /api/v1/license-security, /api/v1/cloud-identity

**Wave 18 Frontend Pages:** MFAManagementDashboard, ThreatScoreDashboard, SecurityBudgetDashboard,
ComplianceGapDashboard (all wired in App.tsx)

**Engine total: 193+ engines | Router total: 420+ endpoints | Test total: 3,000+ tests**

---

### DONE (session 2026-04-16, Wave 19 — Autonomous parallel build)

**Wave 19 New Backend Engines:**
- ✅ dark_web_monitoring_engine.py — DarkWebMonitoring (mentions, keywords, credential exposures, SHA-256 URL hashing) — 63 tests
- ✅ itdr_engine.py — ITDR (identity threats, behavior analytics, response actions, confidence clamping) — 60 tests
- ✅ container_runtime_security_engine.py — ContainerRuntimeSecurity (container lifecycle, violations, runtime policies) — 101 tests
- ✅ api_discovery_engine.py — APIDiscovery (endpoint discovery, undocumented API detection, risk scoring) — 101 tests
- ✅ security_chaos_engine.py — SecurityChaos (chaos experiments, resilience scoring, observations) — 36 tests
- ✅ incident_metrics_engine.py — IncidentMetrics (MTTR/MTTC computation, daily snapshots, SLA config) — 36 tests

**Wave 19 Routers wired:** /api/v1/dark-web, /api/v1/itdr, /api/v1/container-runtime, /api/v1/api-discovery, /api/v1/security-chaos, /api/v1/incident-metrics

**Wave 18+19 Frontend Pages:**
- ✅ AIGovernanceDashboard (/ai-governance), DigitalIdentityDashboard (/digital-identity)
- ✅ AttackChainDashboard (/attack-chains), ThreatExposureDashboard (/threat-exposure)
- ✅ SoftwareLicenseDashboard (/license-security), CloudIdentityDashboard (/cloud-identity)

**Engine total: 204+ engines | Router total: 432+ routers | Test total: 3,300+ tests | Frontend: 175+ pages**

---

### DONE (session 2026-04-16, Wave 20 — Autonomous parallel build)

**Wave 20 New Backend Engines:**
- ✅ zero_day_intelligence_engine.py — ZeroDayIntelligence (vulns/threat actors/mitigations, CVSS, exploitation status) — 37 tests
- ✅ security_tabletop_engine.py — SecurityTabletop (exercises/participants/findings, 8 scenario types, score clamping) — 35 tests
- ✅ browser_security_engine.py — BrowserSecurity (policies/events/extensions, 8 event types, JSON settings) — 36 tests
- ✅ data_exfiltration_engine.py — DataExfiltration (incidents/policies/indicators, 8 incident types, confidence clamping) — 34 tests
- ✅ pki_management_engine.py — PKIManagement (certs/CAs/audit log, revocation, expiry detection) — 35 tests
- ✅ security_tool_inventory_engine.py — SecurityToolInventory (tools/integrations/assessments, cost tracking) — 34 tests

**Wave 20 Routers wired:** /api/v1/zero-day, /api/v1/tabletop, /api/v1/browser-security, /api/v1/data-exfiltration, /api/v1/pki, /api/v1/tool-inventory

**Wave 19+20 Frontend Pages:**
- ✅ DarkWebMonitoringDashboard (/dark-web), ITDRDashboard (/itdr)
- ✅ ContainerRuntimeSecurityDashboard (/container-runtime), APIDiscoveryDashboard (/api-discovery)
- ✅ SecurityChaosDashboard (/security-chaos), IncidentMetricsDashboard (/incident-metrics)

**Engine total: 211+ engines | Router total: 438+ routers | Test total: 3,500+ tests | Frontend: 160+ pages**

---

### DONE (session 2026-04-16, Wave 21 — Autonomous parallel build)

**Wave 21 New Backend Engines:**
- ✅ firmware_security_engine.py — FirmwareSecurity (devices/vulns/scans, 9 device types, scan lifecycle) — 44 tests
- ✅ iot_security_engine.py — IoTSecurity (devices/anomalies/policies, 10 categories, resolve lifecycle) — 49 tests
- ✅ mobile_app_security_engine.py — MobileAppSecurity (apps/findings/scans, OWASP mapping, 5 platforms) — 67 tests
- ✅ api_abuse_detection_engine.py — APIAbuseDetection (endpoints/incidents/rules, 9 abuse types) — 50 tests
- ✅ supply_chain_attack_detection_engine.py — SupplyChainAttackDetection (packages/detections/policies, 8 ecosystems) — 47 tests
- ✅ cloud_workload_protection_engine.py — CloudWorkloadProtection (workloads/threats/policies, 7 cloud providers) — 44 tests

**Wave 21 Routers wired:** /api/v1/firmware-security, /api/v1/iot-security, /api/v1/mobile-app-security, /api/v1/api-abuse, /api/v1/supply-chain-attacks, /api/v1/cwp

**Wave 20+21 Frontend Pages:**
- ✅ ZeroDayIntelligenceDashboard (/zero-day), SecurityTabletopDashboard (/security-tabletop)
- ✅ BrowserSecurityDashboard (/browser-security), DataExfiltrationDashboard (/data-exfiltration)
- ✅ PKIManagementDashboard (/pki-management), SecurityToolInventoryDashboard (/tool-inventory)

**Engine total: 217+ engines | Router total: 444+ routers | Test total: 3,800+ tests | Frontend: 166+ pages**

---

### DONE (session 2026-04-16, Wave 22 — Autonomous parallel build)

**Wave 22 New Backend Engines:**
- ✅ autonomous_remediation_engine.py — AutonomousRemediation (workflows/executions/playbooks, success_rate tracking) — 34 tests
- ✅ vulnerability_correlation_engine.py — VulnerabilityCorrelation (assets/correlations/asset-vulns, JSON round-trip, KEV tracking) — 39 tests
- ✅ security_posture_benchmarking_engine.py — SecurityPostureBenchmarking (benchmarks/controls/comparisons, score recomputed from controls) — 50 tests
- ✅ quantum_safe_crypto_engine.py — QuantumSafeCrypto (assets/assessments/migrations, auto quantum_vulnerable flag, readiness score) — 67 tests
- ✅ ai_powered_soc_engine.py — AIPoweredSOC (detections/models/automation, triage workflow, model accuracy tracking) — 46 tests
- ✅ deception_analytics_engine.py — DeceptionAnalytics (assets/interactions/campaigns, interaction counter, DISTINCT IP count) — 45 tests

**Wave 22 Routers wired:** /api/v1/autonomous-remediation, /api/v1/vuln-correlation, /api/v1/posture-benchmarking, /api/v1/quantum-crypto, /api/v1/ai-soc, /api/v1/deception-analytics

**Wave 21+22 Frontend Pages:**
- ✅ FirmwareSecurityDashboard (/firmware-security), IoTSecurityDashboard (/iot-security)
- ✅ MobileAppSecurityDashboard (/mobile-app-security), APIAbuseDashboard (/api-abuse)
- ✅ SupplyChainAttackDashboard (/supply-chain-attacks), CloudWorkloadProtectionDashboard (/cwp)

**Engine total: 224+ engines | Router total: 454+ routers | Test total: 4,100+ tests | Frontend: 176+ pages**

---

### DONE (session 2026-04-16, Wave 23 — Autonomous parallel build)

**Wave 23 New Backend Engines:**
- ✅ threat_intelligence_automation_engine.py — TIAutomation (feeds/automations/enrichments, SHA-256 key hashing, IOC JSON) — 46 tests
- ✅ security_metrics_aggregator_engine.py — SecurityMetricsAggregator (sources/metrics/aggregations, get_latest_metric) — 39 tests
- ✅ endpoint_threat_hunting_engine.py — EndpointThreatHunting (hunts/findings/iocs, planned→active→completed FSM) — 43 tests
- ✅ cloud_security_analytics_engine.py — CloudSecurityAnalytics (events/anomalies/rules, match_count, rule trigger) — 39 tests
- ✅ identity_risk_engine.py — IdentityRisk (identities/risk factors/access reviews, risk_level auto-update) — 47 tests
- ✅ operational_technology_security_engine.py — OTSecurity (assets/incidents/zones, IEC 62443, Purdue 0-5) — 49 tests

**Wave 23 Routers wired:** /api/v1/ti-automation, /api/v1/metrics-aggregator, /api/v1/endpoint-hunting, /api/v1/cloud-analytics, /api/v1/identity-risk, /api/v1/ot-sec

**Wave 22+23 Frontend Pages:**
- ✅ AutonomousRemediationDashboard (/autonomous-remediation), VulnerabilityCorrelationDashboard (/vuln-correlation)
- ✅ PostureBenchmarkingDashboard (/posture-benchmarking), QuantumCryptoDashboard (/quantum-crypto)
- ✅ AIPoweredSOCDashboard (/ai-soc), DeceptionAnalyticsDashboard (/deception-analytics)

**Engine total: 236+ engines | Router total: 466+ routers | Test total: 4,400+ tests | Frontend: 188+ pages**

---

### DONE (session 2026-04-16, Wave 24 — Autonomous parallel build)

**Wave 24 New Backend Engines:**
- ✅ network_forensics_engine.py — NetworkForensics (captures, artifacts, analyze, forensics stats) — 38 tests
- ✅ malware_analysis_engine.py — MalwareAnalysis (samples, verdicts, IOC extraction, stats) — 38 tests
- ✅ application_risk_engine.py — ApplicationRisk (app registration, risk scoring, findings lifecycle) — ~40 tests
- ✅ privileged_access_governance_engine.py — PAG (PA accounts, sessions, anomaly detection) — ~39 tests
- ✅ security_awareness_gamification_engine.py — SAGamification (challenges, completions, leaderboard, badges) — ~39 tests
- ✅ vulnerability_prioritization_engine.py — VulnPrioritization (CVSS+EPSS+KEV priority scoring, remediation queue) — ~39 tests

**Wave 24 Routers wired:** /api/v1/network-forensics, /api/v1/malware-analysis, /api/v1/app-risk, /api/v1/pag, /api/v1/awareness-gamification, /api/v1/vuln-prioritization

**Wave 24 Frontend Pages (Wave 23 domains):**
- ✅ ThreatIntelAutomation (/threat-intel-automation), MetricsAggregatorDashboard (/metrics-aggregator)
- ✅ EndpointHuntingDashboard (/endpoint-hunting), CloudSecurityAnalyticsDashboard (/cloud-security-analytics)
- ✅ IdentityRiskDashboard (/identity-risk), OTSecurityDashboard (/ot-security)

**Engine total: 242+ engines | Router total: 472+ routers | Test total: 4,600+ tests | Frontend: 194+ pages**

---

## OPERATING RULES

1. **YOU ARE CTO** — delegate via `/team` or subagents, don't write code
2. **AUTO-SAVE every 15-20 minutes** — commit + push, no exceptions
3. **Run Beast Mode tests only** — not the full 14K test suite
4. **Zero regressions** — if Beast Mode tests fail, fix before moving on
5. **Extend existing code, don't rebuild** — 52 native tools already exist
6. **Every feature serves at least one of the 30 personas**
7. **Commit format**: `beast-mode(feature): description` with `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`

---

## GIT CONFIG

- **Repo**: `DevOpsMadDog/Fixops`
- **Branch**: `features/intermediate-stage`
- **User**: DevOpsMadDog | Email: info@devopsai.co

---

## CONVENTIONS

- **Python**: FastAPI + Pydantic v2. Type hints. structlog logging.
- **Routers**: `*_router.py` with `router = APIRouter(prefix=...)`.
- **Auth**: `Depends(_verify_api_key)` or `require_auth`.
- **DB**: SQLite per domain. `PersistentDict` pattern.
- **Tests**: `test_*.py` in `tests/`. pytest-asyncio. 10s timeout.
- **UI**: Work in `suite-ui/aldeci-ui-new/` only. React 19, Vite 6, Tailwind v4.

---

## EXISTING INVENTORY (DO NOT REBUILD)

| Component | Count | Location |
|-----------|-------|----------|
| PULL connectors | 13 | suite-core/core/security_connectors.py |
| Bidirectional connectors | 7 | suite-core/core/connectors.py |
| Scanner normalizers | 32 | suite-core/core/scanner_parsers.py |
| Threat intel feeds | 28+ | suite-feeds/ |
| Backend engines | 236+ | suite-core/core/*_engine.py |
| API router files | 466+ | suite-api/apps/api/*_router.py |
| Engine test files | 240+ | tests/test_*_engine.py |
| Frontend pages | 188+ | suite-ui/aldeci-ui-new/src/pages/ |
| Beast Mode tests | 4,400+ | tests/test_phase*.py + engine tests |

---

## RECENT CHANGES (2026-04-16, Wave 6+7+8 — Continuous autonomous build)

### Beast Mode Tests: 709 base + 700+ new = 1,400+ total (zero regressions)
### UI: 97+ pages total, builds clean, 320+ router files, 8 pages wired to live APIs
### API: 850+ endpoints across 105+ routers

### Wave 6 Backend Engines (all in suite-core/core/):
- ✅ posture_score_engine.py — Security Posture Scoring — 35 tests
- ✅ threat_feed_aggregator.py — Multi-source threat feed aggregation — 25 tests
- ✅ digital_forensics_engine.py — Digital Forensics & Incident Response — 29 tests
- ✅ security_roadmap_engine.py — Security Roadmap & Maturity Planning — 36 tests
- ✅ data_governance_engine.py — Data Governance & Classification — 40 tests
- ✅ compliance_scanner_engine.py — Automated Compliance Scanning — 58 tests
- ✅ asset_risk_calculator.py — Asset Risk Scoring Calculator — 34 tests
- ✅ security_health_engine.py — Security Health Monitoring — 35 tests
- ✅ incident_timeline_engine.py — Incident Timeline Reconstruction — 32 tests
- ✅ security_metrics_collector.py — Cross-domain Metrics Collection — 36 tests
- ✅ devsecops_engine.py — DevSecOps Pipeline Integration — 40 tests
- ✅ vuln_trend_engine.py — Vulnerability Trend Analysis — 27 tests
- ✅ config_benchmark_engine.py — CIS/STIG Configuration Benchmarking — 26 tests
- ✅ threat_model_generator.py — Automated Threat Model Generation — 35 tests
- ✅ security_exception_engine.py — Security Exception Workflow — 28 tests
- ✅ analytics_engine.py — DuckDB cross-domain analytics — 50 tests
- ✅ attack_simulation_engine.py — AttackSimulationDbEngine added — 31 tests

### Wave 7 Backend Engines (all in suite-core/core/):
- ✅ regulatory_tracker_engine.py — Regulatory Change Tracking — 34 tests
- ✅ security_scorecard_engine.py — Security Scorecard & Grading — 36 tests
- ✅ ccm_engine.py — Cloud Controls Matrix engine — 31 tests
- ✅ awareness_score_engine.py — Security Awareness Scoring
- ✅ ndr_engine.py — Network Detection & Response — 33 tests
- ✅ xdr_engine.py — Extended Detection & Response — 33 tests
- ✅ edr_engine.py — Endpoint Detection & Response — 31 tests
- ✅ supply_chain_intel_engine.py — Supply Chain Intelligence — 32 tests
- ✅ threat_hunting_engine.py — Proactive Threat Hunting — 67 tests
- ✅ identity_analytics_engine.py — Identity Analytics & Risk — 34 tests
- ✅ cnapp_engine.py — Cloud-Native Application Protection — 37 tests
- ✅ pentest_mgmt_engine.py — Pentest Management — 32 tests
- ✅ threat_intel_sharing_engine.py — STIX 2.1 threat sharing — 35 tests

### Wave 8 Backend Engines (all in suite-core/core/):
- ✅ security_champions_engine.py — Security Champions Program — 36 tests
- ✅ red_team_mgmt_engine.py — Red Team Management — 38 tests
- ✅ data_classification_engine.py — Data Classification & PII — 45 tests
- ✅ threat_actor_engine.py — Threat Actor Intelligence — 44 tests
- ✅ application_security_engine.py — AppSec SAST/DAST aggregation — 30 tests
- ✅ bug_bounty_engine.py — Bug Bounty Program Management — 30 tests
- ✅ deception_engine.py — Canary tokens, honeypots — 28 tests (newly covered)
- ✅ dast_engine.py — Dynamic App Security Testing — 26 tests (newly covered)
- ✅ sbom_engine.py — SBOM CycloneDX/SPDX generation — 27 tests (newly covered)
- ✅ ir_playbook_engine.py — IR Playbooks with MTTD/MTTR — 30 tests (newly covered)
- ✅ supply_chain_risk_engine.py — Supply Chain Risk — 28 tests (newly covered)
- ✅ ai_security_advisor_engine.py — LLM-powered advisor (Qwen 3.6 Max) — ~30 tests
- ✅ scheduled_reports_engine.py — Scheduled reports + Slack delivery — ~30 tests

### Router Wiring (session 2026-04-16, all missing routers now wired):
- ✅ phishing_simulation_router — /api/v1/phishing
- ✅ ioc_enrichment_router — /api/v1/ioc-enrichment
- ✅ ctem_router — /api/v1/ctem
- ✅ workflow_router — /api/v1/workflows
- ✅ policy_router — /api/v1/policies
- ✅ security_playbook_router — /api/v1/security-playbooks
- ✅ analytics_engine_router — /api/v1/analytics
- ✅ attack_simulation_router — /api/v1/attack-sim
- ✅ compliance_router — /api/v1/compliance
- ✅ data_classification_router — /api/v1/data-classification
- ✅ threat_actor_router — /api/v1/threat-actors
- ✅ security_champions_router — /api/v1/security-champions
- ✅ red_team_mgmt_router — /api/v1/red-team
- ✅ application_security_router — /api/v1/appsec
- ✅ bug_bounty_router — /api/v1/bug-bounty
- ✅ ai_security_advisor_router — /api/v1/ai-advisor
- ✅ scheduled_reports_router — /api/v1/scheduled-reports

### Frontend Pages (wave 6+7, new — all in suite-ui/aldeci-ui-new/src/pages/):
- ✅ /asset-risk — AssetRiskDashboard
- ✅ /attack-simulation — AttackSimulation
- ✅ /audit-log — AuditLog
- ✅ /breach-response — BreachResponse
- ✅ /bug-bounty — BugBounty
- ✅ /cert-manager — CertificateManager
- ✅ /cloud-iam — CloudIAM
- ✅ /cloud-security — CloudSecurityDashboard
- ✅ /cmdb — CMDBDashboard
- ✅ /compliance-scanner — ComplianceScannerDashboard
- ✅ /config-benchmark — ConfigBenchmarkDashboard
- ✅ /cross-domain-analytics — CrossDomainAnalytics (DuckDB)
- ✅ /cspm — CSPMDashboard
- ✅ /cwpp — CWPPDashboard
- ✅ /cyber-insurance — CyberInsurance
- ✅ /data-classification — DataClassificationDashboard
- ✅ /data-governance — DataGovernanceDashboard
- ✅ /deception-engine — DeceptionEngine
- ✅ /devsecops — DevSecOpsDashboard
- ✅ /digital-forensics — DigitalForensicsDashboard
- ✅ /container-security — ContainerSecurity
- ✅ /email-security — EmailSecurity
- ✅ /endpoint-security — EndpointSecurity
- ✅ /executive-briefing — ExecutiveBriefing
- ✅ /executive-risk-report — ExecutiveRiskReport
- ✅ /firewall-analyzer — FirewallAnalyzer
- ✅ /grc-assessment — GRCAssessment
- ✅ /grc — GRCDashboard
- ✅ /identity-governance — IdentityGovernance
- ✅ /incident-response — IncidentResponseDashboard
- ✅ /incident-timeline — IncidentTimelineDashboard
- ✅ /ioc-hunter — IOCHunter
- ✅ /mobile-security — MobileSecurity
- ✅ /network-analysis — NetworkAnalysis
- ✅ /network-topology — NetworkTopology
- ✅ /pam — PAMDashboard
- ✅ /password-policy — PasswordPolicy
- ✅ /pentest-management — PentestManagement
- ✅ /phishing-simulation — PhishingSimulation
- ✅ /playbook-library — PlaybookLibrary
- ✅ /red-team — RedTeamStatus
- ✅ /risk-quantification — RiskQuantification
- ✅ /risk-register — RiskRegister
- ✅ /security-awareness — SecurityAwareness
- ✅ /security-exception — SecurityExceptionDashboard
- ✅ /security-health — SecurityHealthDashboard
- ✅ /security-metrics — SecurityMetricsDashboard
- ✅ /security-operations — SecurityOperationsCenter
- ✅ /security-posture — SecurityPostureDashboard
- ✅ /security-roadmap — SecurityRoadmap
- ✅ /security-training — SecurityTrainingDashboard
- ✅ /sla — SLADashboard
- ✅ /soar — SOARDashboard
- ✅ /social-engineering — SocialEngineering
- ✅ /supply-chain-dashboard — SupplyChainDashboard
- ✅ /threat-correlation — ThreatCorrelation
- ✅ /threat-feed — ThreatFeedDashboard
- ✅ /threat-hunting — ThreatHuntingDashboard
- ✅ /threat-model — ThreatModelDashboard
- ✅ /uba — UBADashboard
- ✅ /vuln-heatmap — VulnHeatmap
- ✅ /vuln-risk-queue — VulnRiskQueue
- ✅ /vuln-trends — VulnTrendDashboard
- ✅ /watchlist — WatchlistManager
- ✅ /zero-trust-policy — ZeroTrustPolicyDashboard
- ✅ /api-security — APISecurityDashboard
- ✅ /app-security — AppSecurity

### Business Layer:
- ✅ Investor Pitch Deck ($2M seed ask, 5-year projections) — docs/INVESTOR_PITCH.md
- ✅ Competitive Analysis (vs Wiz/Lacework/Snyk/Rapid7/Tenable) — docs/COMPETITIVE_ANALYSIS.md
- ✅ Go-to-Market Strategy (3-phase, 3 sales playbooks) — docs/GO_TO_MARKET.md
- ✅ README.md rewritten (acquisition-grade)
- ✅ Demo data seeder (10 engines, investor-quality) — scripts/seed_demo_data.py

### Storage Technology:
- ✅ DuckDB analytics layer (cross-domain queries across all 60+ SQLite engines) — duckdb>=0.10.0 in requirements.txt
- SQLite: 98 domain databases (correct for embedded CRUD per-engine)
- MD files: docs only (correct use)

### Security Fixes (all 4 multi-tenant findings from b9d5aabe resolved):
- ✅ Redis queue keys now org_id-scoped — redis_queue.py
- ✅ attack_path get/remove nodes guarded by org_id — attack_path_engine.py
- ✅ sso_sessions/sso_providers tables have org_id column — sso_bridge.py
- ✅ insider threat resolve_alert() has org_id guard — insider_threat_engine.py

### Git state: features/intermediate-stage

---

## BEAST MODE TOOL INSTALLATION & LOCATIONS

### Prerequisites
- Docker + Docker Compose
- Node.js (for npm)
- Homebrew (macOS) or apt (Linux)

### One-Shot Setup
```bash
cd ../best-mode-dev-framework
chmod +x setup.sh && ./setup.sh
```

### Start Beast Mode (from beast-mode-dev-framework, NOT from Fixops)
```bash
cd ../best-mode-dev-framework
./start.sh ../Fixops
```
This starts Layer 2 Docker services, rebuilds code-review-graph if stale, then launches Claude Code pointing at Fixops. Claude reads this CLAUDE.md and operates as CTO.

### Setup Details
This runs 11 steps:
1. Checks prerequisites (docker, docker-compose)
2. Installs Layer 1 (OMC, everything-claude-code skills, OMNI, Context7)
3. Installs Ollama (local LLM inference)
4. Pulls Gemma 7B model (~4GB download)
5. Prompts for OpenRouter API key (free — for Qwen 3.6+, DeepSeek V3)
6. Installs Layer 2 (SwarmClaw config)
7. Starts Docker containers (SwarmClaw, TrustGraph, Ollama, Redis, PostgreSQL)
8. Indexes codebase into TrustGraph
9. Seeds Kanban board with tasks
10. Prints summary with URLs

### Where Tools Live After Install

| Tool | Install Location | How To Access | Port |
|------|-----------------|---------------|------|
| **code-review-graph** | `pip install code-review-graph` | `code-review-graph stats/query/impact` — **USE FIRST** | — |
| OMC (oh-my-claudecode) | Claude Code plugin marketplace | `/team`, `omc autoresearch`, `omc ask` | — |
| everything-claude-code | `~/.claude-skills/ecc/` | Auto-loads based on context | — |
| OMNI | `npm -g` or `pip` global | `omni` CLI | — |
| Context7 MCP | Claude MCP config | Auto-available in Claude Code | — |
| SwarmClaw | Docker: `beast-swarmclaw` | Dashboard: http://localhost:3456 | 3456 |
| TrustGraph | `pip install trustgraph-cli` | Config: https://config-ui.demo.trustgraph.ai | 8888 |
| Ollama | Docker: `beast-ollama` OR native install | API: http://localhost:11434 | 11434 |
| Redis | Docker: `beast-redis` | localhost:6379 | 6379 |
| PostgreSQL | Docker: `beast-postgres` | localhost:5432 (user: swarmclaw) | 5432 |

### Docker Services (Layer 2)
```bash
cd ../best-mode-dev-framework/layer2-swarmclaw-autonomous

# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f

# Stop
docker compose down
```

### OpenRouter API Key (FREE models)
Sign up at https://openrouter.ai — free tier gives access to:
- Qwen 3.6 Plus (code-builder + test-writer agents) — qwen/qwen3.6-plus:free
- Kimi K2 (security + code reviewer council) — moonshotai/kimi-k2:free
- Gemma 4 (doc-generator, local via Ollama)
- Llama 4 (general tasks)

Save key in: `../best-mode-dev-framework/layer2-swarmclaw-autonomous/.env`
```
OPENROUTER_API_KEY=sk-or-v1-xxxxx
```

### Quick Verify Everything Works
```bash
# Check Layer 1
which omc && echo "OMC: OK" || echo "OMC: NOT INSTALLED"
ls ~/.claude-skills/ecc/ && echo "ECC: OK" || echo "ECC: NOT INSTALLED"
ollama --version && echo "Ollama: OK" || echo "Ollama: NOT INSTALLED"

# Check Layer 2 (Docker)
docker ps --format "{{.Names}}: {{.Status}}" | grep beast
# Should show: beast-swarmclaw, beast-ollama, beast-redis, beast-postgres

# Check SwarmClaw API
curl -s http://localhost:3456/api/healthz | head -1

# Check TrustGraph CLI
tg --version 2>/dev/null || echo "Install: pip install trustgraph-cli"
```

---

*Source of truth: `docs/ALDECI_REARCHITECTURE_v2.md` (v2.5). Beast Mode framework: `../best-mode-dev-framework/`*
