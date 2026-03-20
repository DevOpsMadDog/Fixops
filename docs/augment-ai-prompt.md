# ALdeci CTEM+ — Augment AI (Auggie) Master Prompt

> Paste this into Auggie. Optimized for Claude 4.6 — structured for chain-of-thought reasoning, explicit constraints, and measurable exit criteria.

---

You are acting as **CTO and Principal Engineer** for ALdeci, a CTEM+ Decision Intelligence Platform for Application Security. Your job is to transform this from a working prototype into a product that beats Apiiro and Aikido on every dimension — depth, reliability, UX, and enterprise readiness.

## System Architecture (Read First)

```
Monolith: 6 Python suites on one FastAPI app (port 8000), 1,029 API routes

suite-api/          → FastAPI gateway, 34 router mounts, JWT + API key auth
suite-core/         → Brain pipeline, FAIL scoring, knowledge graph, scanners, CLI
suite-attack/       → MPTE micro-pentest engine, attack simulation, SAST, DAST, CSPM, container security
suite-feeds/        → NVD, KEV, EPSS, OSV, ExploitDB threat intel
suite-evidence-risk/ → Evidence bundles, risk scoring, compliance frameworks, secrets detection
suite-integrations/ → Jira, Confluence, Slack, ServiceNow, GitHub, GitLab, Azure DevOps, MCP, IaC, webhooks, IDE

suite-ui/aldeci-ui-new/ → Official UI: React 19 + Vite 6 + Tailwind v4 + Zustand + Recharts
                          60+ pages, 5 Workflow Spaces, RBAC, dark mode

Entry point:  suite-api/apps/api/app.py (create_app factory)
Import mechanism: sitecustomize.py auto-prepends all suite dirs to sys.path
Database: SQLite WAL (56 .db files, PersistentDict pattern)
Tests: 7,500+ passing, pytest with 10s timeout
CLI: suite-core/core/cli.py (5,929 LOC, 22 commands)
```

## What's Working (Don't Break These)

- Brain pipeline (12-step CTEM orchestration) with real EPSS/KEV enrichment (3,564 LOC)
- FAIL scoring engine with real risk computation (717 LOC)
- 8 native scanners (real HTTP-based vulnerability detection)
- Analytics with real statistical computation (z-scores, moving averages)
- Nerve center with real health probes and composite threat scoring
- Developer risk profiles engine (913 LOC, real metrics)
- Webhook subscription system (1,922 LOC, bidirectional)
- Evidence bundles with RSA-SHA256 + ML-DSA signing (2,668 LOC crypto engine)
- 7 integration connectors with full CRUD (3,029 LOC)
- 10 security tool connectors (Snyk, SonarQube, Dependabot, AWS SecurityHub, Azure Defender, Wiz, Prisma Cloud, Orca, Lacework, ThreatMapper — 1,815 LOC)
- Micro-pentest engine (2,054 LOC core + 1,088 LOC advanced)
- Knowledge graph with SQLite+NetworkX (945 LOC engine + 658 LOC router)
- Compliance engine (2,043 LOC)
- Risk scoring with ML (sklearn GBT, bootstrap CIs, SHAP-like explainability)
- AutoFix engine (1,748 LOC, LLM-powered with 10 fix types)
- OpenAPI spec generates cleanly (930 paths)
- App starts with 1,029 routes, all key endpoints verified

## What's Broken (Fix These — Priority Order)

### P0: UI Screens Are Disconnected from Real APIs

The UI has 60+ pages across 5 Workflow Spaces but most show hardcoded/mock data. This is the single biggest gap between us and a shippable product.

**5 Workflow Spaces and their route structure:**

| Space | Route | What Users Expect | Current State |
|-------|-------|-------------------|---------------|
| Mission Control | `/command` | Live KPIs, risk trends, alert feed, system health | KPI cards show static numbers, charts use fake data |
| Discover | `/discover` | Finding explorer, asset map, scanner results, SBOM | Tables render but don't paginate/filter via API |
| Prioritize | `/prioritize` | AI triage queue, brain pipeline results, FAIL scores | Triage queue exists but doesn't call `/api/v1/brain/pipeline` |
| Remediate | `/remediate` | Fix tracking, AutoFix dashboard, Jira sync, SLA | Remediation center has buttons that don't trigger API calls |
| Prove | `/prove` | Evidence bundles, compliance dashboard, reports, audit trail | Compliance shows frameworks but coverage % is hardcoded |

**For every screen, you must:**
1. Find the React component in `suite-ui/aldeci-ui-new/src/pages/`
2. Identify every data display (KPI card, table, chart, list)
3. Find or create the matching `/api/v1/` endpoint
4. Wire the component to fetch real data using the existing API client (`src/lib/api.ts`)
5. Add loading states, error states, empty states
6. Ensure buttons/forms trigger real mutations (POST/PUT/DELETE)
7. Ensure navigation drill-downs work (Dashboard card click -> detail page)

### P1: Buttons and Actions Don't Work

Across the UI, buttons exist but many either:
- Do nothing (no onClick handler)
- Open a modal that can't submit (form not wired to API)
- Show "Coming Soon" or fail silently
- Navigate to a dead-end page

**Fix pattern:**
```typescript
// BEFORE (broken)
<Button onClick={() => {}}>Run Scan</Button>

// AFTER (working)
<Button
  onClick={async () => {
    setLoading(true);
    try {
      const result = await api.post('/api/v1/scanner/scan', payload);
      toast.success('Scan started');
      router.push(`/discover/scans/${result.data.scan_id}`);
    } catch (err) {
      toast.error(err.response?.data?.detail || 'Scan failed');
    } finally {
      setLoading(false);
    }
  }}
  disabled={loading}
>
  {loading ? 'Scanning...' : 'Run Scan'}
</Button>
```

### P2: Sub-screens and Modals Need Real Data

Many drawer/modal components open but display empty or placeholder content. Each must:
- Fetch data on open (not on page load)
- Show a loading skeleton while fetching
- Display real data from the correct endpoint
- Support CRUD operations where appropriate
- Close and refresh the parent view on success

### P3: Navigation and Breadcrumbs

- Sidebar navigation must highlight the active space and page
- Breadcrumbs must show the full path: Space > Page > Detail
- Back buttons must work (not just `router.push('/')`)
- Related screens must cross-link (Finding -> Remediation -> Evidence)

---

## Competitive Gap Analysis — API Depth Enhancement Plan

This is the most critical section. Before building anything, understand what Apiiro and Aikido offer, what ALdeci already has, and where the gaps are. **Every gap listed below must be closed with real implementation, not stubs.**

### Domain 1: Risk Scoring & Risk Graph

**Apiiro has**: Risk Graph™ — correlates code changes with runtime risk, maps developer behavior to risk profiles, identifies "crown jewel" applications, quantifies blast radius across the entire software supply chain. Their Risk Graph is their core differentiator.

**Aikido has**: Auto-triage with 95% noise reduction, severity scoring with reachability analysis, risk-based prioritization across all scanner findings.

**ALdeci has**:
- `suite-core/core/fail_engine.py` (717 LOC) — FAIL scoring with 4-axis computation (Frequency, Attack surface, Impact, Lifecycle)
- `suite-evidence-risk/risk/scoring.py` (466 LOC) — ML-based risk scoring with sklearn GBT + SHAP
- `suite-core/core/brain_pipeline.py` (3,564 LOC) — 12-step pipeline with correlation
- `suite-core/core/services/enterprise/knowledge_graph.py` (945 LOC) — SQLite+NetworkX graph with BFS, path finding
- `suite-core/core/developer_risk_profiler.py` (913 LOC) — Developer behavior scoring

**Gap to close**: ALdeci has the individual engines but they're NOT connected into a unified Risk Graph that cross-references. The brain pipeline runs them sequentially but doesn't build a persistent, queryable graph.

**Action**:
- Wire knowledge graph to ingest brain pipeline output after every run
- Add `/api/v1/risk/graph` endpoint that returns a unified risk topology (assets → findings → developers → code changes → runtime context)
- Add blast radius computation: given a finding, show all affected assets, teams, and compliance controls
- Wire the UI Risk Graph page to render this as an interactive force-directed graph
- API: `GET /api/v1/risk/graph/topology` → nodes + edges, `GET /api/v1/risk/graph/blast-radius/{finding_id}` → impact cascade

### Domain 2: Code Analysis / SAST

**Apiiro has**: Deep Code Analysis (DCA) — proprietary static analysis that understands code semantics, not just patterns. Identifies material vs. cosmetic changes. Tracks risk at the design phase.

**Aikido has**: AI-powered SAST using their OpenGrep fork (Semgrep-based), real-time analysis in CI/CD, language-specific rules for 20+ languages.

**ALdeci has**:
- `suite-attack/api/sast_router.py` (160 LOC) — SAST API with scan endpoints
- `suite-core/core/scanners/` — 8 native scanners (dependency, secret, SAST, container, IaC, API, XSS, SQLi)
- Scanner ingest pipeline processes results from external tools (Snyk, SonarQube, etc.)

**Gap to close**: SAST router is thin (160 LOC). Real depth comes from scanner ingest + external tool connectors. We need deeper material change detection and design-time analysis.

**Action**:
- In `sast_router.py`, add `POST /api/v1/sast/analyze` that accepts a git diff and runs pattern-based detection for top 25 CWEs
- Add `POST /api/v1/sast/material-change` — analyze a commit/PR and classify as material (security-relevant) vs cosmetic (formatting, comments, refactoring)
- Wire to `suite-core/core/cli.py` scan commands so UI scan → API → CLI → results → UI display
- Add `GET /api/v1/sast/rules` endpoint to list/manage detection rules
- API depth target: 10+ endpoints covering scan, analyze, rules CRUD, findings, diff-analysis

### Domain 3: Supply Chain / SBOM / SCA

**Apiiro has**: XBOM (extended SBOM) — goes beyond dependencies to include APIs, microservices, data models, sensitive data flows. Deep reachability analysis shows if vulnerabilities are actually exploitable in context.

**Aikido has**: SCA with reachability analysis, malware detection in dependencies, license compliance, SBOM generation (CycloneDX/SPDX), dependency graph visualization.

**ALdeci has**:
- `suite-api/apps/api/normalizers.py` — InputNormalizer with CycloneDX/SPDX/SARIF parsing
- `suite-evidence-risk/risk/dependency_graph.py` (236 LOC) — Dependency graph
- `suite-evidence-risk/risk/dependency_health.py` (261 LOC) — Health scoring
- `suite-evidence-risk/risk/dependency_realtime.py` (368 LOC) — Real-time monitoring
- `suite-evidence-risk/risk/license_compliance.py` (241 LOC) — License checking
- `suite-feeds/api/feeds_router.py` — NVD/KEV/EPSS/OSV feed integration
- gap_router.py has SBOM endpoints but delegates to weak inline parser

**Gap to close**: SBOM parsing works but reachability analysis is missing. No malware detection in dependencies. Dependency graph exists but isn't wired to the UI SBOM page.

**Action**:
- Wire `dependency_graph.py` + `dependency_health.py` + `license_compliance.py` to dedicated API endpoints (not just internal modules)
- Add `POST /api/v1/sbom/analyze` → full SBOM analysis returning: components, vulnerabilities with reachability verdict, license risks, health scores
- Add `GET /api/v1/sbom/dependency-graph/{sbom_id}` → returns graph data for UI visualization
- Add `POST /api/v1/sbom/reachability` → given a vulnerability + SBOM, determine if the vulnerable function is actually called
- Wire to `suite-feeds` for real-time enrichment: each component → check NVD + OSV + EPSS for known CVEs
- API depth target: 12+ endpoints covering upload, parse, analyze, graph, reachability, license, health, export

### Domain 4: Container & Cloud Security / CSPM

**Apiiro has**: Code-to-cloud risk mapping — traces vulnerabilities from source code through CI/CD to deployed containers and cloud resources.

**Aikido has**: Container scanning, CSPM (AWS/Azure/GCP), VM scanning, Kubernetes posture management, cloud drift detection, Docker image analysis.

**ALdeci has**:
- `suite-attack/api/container_security_router.py` — Container security endpoints (present but not verified for depth)
- `suite-attack/api/cspm_router.py` (166 LOC) — Cloud security posture management
- Gap router has container and cloud endpoints

**Gap to close**: Container and CSPM routers are thin. Need real Docker image analysis, K8s manifest scanning, and cloud config assessment.

**Action**:
- Enhance `container_security_router.py` to support: `POST /api/v1/containers/scan-image` (accept image name or Dockerfile), `GET /api/v1/containers/images` (inventory), `GET /api/v1/containers/vulnerabilities` (findings in containers)
- Enhance `cspm_router.py` to support: `POST /api/v1/cspm/assess` (scan cloud config), `GET /api/v1/cspm/findings` (misconfigurations), `GET /api/v1/cspm/benchmarks` (CIS Benchmarks compliance)
- Add K8s posture: `POST /api/v1/k8s/scan-manifest` → analyze YAML for security issues (privileged containers, host networking, missing resource limits)
- Wire container findings to knowledge graph for code-to-cloud tracing
- API depth target: 15+ endpoints across containers, CSPM, K8s

### Domain 5: CI/CD Integration & Security Gates

**Apiiro has**: Design-time risk assessment in PRs, build pipeline guardrails, automatic approval gates based on risk level.

**Aikido has**: One-click CI/CD integration (GitHub Action, GitLab CI, Bitbucket Pipelines), PR decoration with inline findings, build-breaking gates with configurable thresholds.

**ALdeci has**:
- `suite-api/apps/api/ci_cd_integration_router.py` — CI/CD integration API
- `suite-core/core/cli.py` (5,929 LOC, 22 commands) — Full CLI for pipeline integration
- Webhook subscription system for PR events

**Gap to close**: CI/CD router exists but need PR decoration, configurable gate policies, and one-command CI setup.

**Action**:
- Add `POST /api/v1/ci-cd/check-pr` → accept PR metadata (repo, branch, diff stats, findings count), return pass/fail against policy + inline comments
- Add `POST /api/v1/ci-cd/gate-evaluate` → evaluate a set of findings against configurable policies (block on critical, warn on high, etc.)
- Add `GET /api/v1/ci-cd/setup/{platform}` → return ready-to-use config for GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket Pipelines
- Wire CLI `scan` command to CI/CD pipeline: `fixops scan --ci --gate-policy=strict --fail-on=critical,high`
- Add `GET /api/v1/ci-cd/runs` → history of CI/CD evaluations with pass/fail status
- API depth target: 10+ endpoints covering setup, evaluation, history, policy CRUD

### Domain 6: AutoFix / Remediation

**Apiiro has**: AutoFix Agent — generates fixes across design, code, and delivery stages. Context-aware (understands the codebase, not just the finding).

**Aikido has**: One-click auto-fix with automatic PR generation. Shows exact fix code, not just the problem description. Supports 10+ languages.

**ALdeci has**:
- `suite-core/core/autofix_engine.py` (1,748 LOC) — LLM-powered engine with 10 fix types (XSS, SQLi, path traversal, deserialization, hardcoded creds, broken crypto, XXE, SSRF, OS command injection, info disclosure)
- AutoFix router with suggest, apply, verify, history endpoints

**Gap to close**: AutoFix works with LLM keys but produces empty patches without them. Need offline template library for top CWEs. Need PR generation (create actual git branches and PRs with fix code).

**Action**:
- Add `POST /api/v1/autofix/generate-pr` → given a finding + fix suggestion, create a git branch, apply the fix, open a PR in the connected SCM (GitHub/GitLab/Azure DevOps)
- Add `POST /api/v1/autofix/batch` → auto-fix multiple findings at once
- Add `GET /api/v1/autofix/templates` → list available offline fix templates (no LLM needed)
- Wire autofix to connectors.py (GitHub/GitLab) for real PR creation
- Add `POST /api/v1/autofix/validate` → after fix is applied, re-scan to confirm the vulnerability is resolved
- Wire UI Remediation Center to show before/after code diff for each fix
- API depth target: 12+ endpoints covering suggest, apply, validate, PR generation, batch, templates, history

### Domain 7: Compliance / GRC

**Apiiro has**: PCI-DSS v4, NIST 800-53, SOC2 compliance mapping. Automated evidence collection from code and pipeline activity.

**Aikido has**: Framework dashboards, automated compliance reports, integration with Vanta and Drata.

**ALdeci has**:
- `suite-evidence-risk/compliance/compliance_engine.py` (2,043 LOC) — Real compliance engine
- `suite-evidence-risk/compliance/mapping.py` (306 LOC) — Framework-to-control mapping
- Evidence router with bundle creation, verification, export
- Crypto signing (RSA-SHA256 + ML-DSA post-quantum)

**Gap to close**: Compliance engine is robust but needs more framework coverage and real evidence auto-collection.

**Action**:
- Ensure all 6 frameworks have full control mapping: PCI-DSS v4, NIST 800-53, SOC2, ISO 27001, HIPAA, OWASP ASVS
- Add `POST /api/v1/compliance/auto-collect` → automatically gather evidence from scan results, CI/CD runs, policy decisions, and triage actions
- Add `GET /api/v1/compliance/coverage/{framework}` → real percentage based on actual evidence vs required controls
- Add `GET /api/v1/compliance/export/{framework}` → export compliance report as PDF/CSV for auditors
- Add `POST /api/v1/compliance/attestation` → create signed attestation from evidence bundle
- Wire UI Compliance Dashboard to show real coverage % from compliance_engine, not hardcoded numbers
- API depth target: 15+ endpoints covering frameworks, controls, evidence, attestation, export, audit trail

### Domain 8: API Security

**Apiiro has**: Code-level API discovery — finds API endpoints in source code and maps them to runtime endpoints. Identifies shadow APIs.

**Aikido has**: API fuzzing, endpoint discovery, authentication testing, rate limit testing.

**ALdeci has**:
- `suite-attack/api/api_fuzzer_router.py` (128 LOC) — API fuzzing
- `suite-attack/api/dast_router.py` (167 LOC) — Dynamic testing
- OpenAPI spec introspection (the app generates its own spec with 930 paths)

**Gap to close**: API security routers are thin. Need API inventory management, shadow API detection, and comprehensive fuzzing sequences.

**Action**:
- Enhance `api_fuzzer_router.py`: `POST /api/v1/api-security/fuzz` → accept an OpenAPI spec or URL, run authentication bypass, injection, rate limit, and broken access control fuzzing
- Add `POST /api/v1/api-security/discover` → given a codebase URL or OpenAPI spec, discover and inventory all API endpoints
- Add `GET /api/v1/api-security/inventory` → list all discovered APIs with last-tested date, risk score, auth method
- Add `POST /api/v1/api-security/test-auth` → test authentication mechanisms (JWT handling, API key rotation, OAuth flows)
- Wire DAST router to run real HTTP-based tests against target APIs
- API depth target: 10+ endpoints covering discovery, inventory, fuzzing, auth testing, findings

### Domain 9: Secrets Detection

**Apiiro has**: Secrets detection with automatic validation (checks if detected keys are still active), grouping related secrets, rotation guidance.

**Aikido has**: BetterLeaks — their own secret scanner, detects 100+ secret types, validates tokens against provider APIs, provides rotation instructions.

**ALdeci has**:
- `suite-evidence-risk/risk/secrets_detection.py` (237 LOC) — Secret detection module
- Native secret scanner in `suite-core/core/scanners/`

**Gap to close**: Secrets detection exists but is basic. Need validation (are these secrets still active?), rotation guidance, and provider-specific handling.

**Action**:
- Enhance `secrets_detection.py` to support 50+ patterns (AWS keys, GCP service accounts, Azure tokens, GitHub tokens, Slack webhooks, database connection strings, private keys, JWT secrets, etc.)
- Add `POST /api/v1/secrets/validate` → for each detected secret, check if it's still active by making a safe API call to the provider
- Add `POST /api/v1/secrets/scan` → scan a repo/directory/file for secrets
- Add `GET /api/v1/secrets/findings` → list all detected secrets with status (active/revoked/unknown)
- Add `POST /api/v1/secrets/rotate-guide` → given a secret type, return step-by-step rotation instructions
- API depth target: 8+ endpoints covering scan, validate, findings, rotation, severity classification

### Domain 10: IaC Scanning

**Apiiro has**: IaC misconfiguration detection for Terraform, CloudFormation, Kubernetes, Helm, Docker.

**Aikido has**: IaC scanning in CI/CD, supports Terraform, CloudFormation, Kubernetes, Docker, Ansible, Pulumi.

**ALdeci has**:
- `suite-integrations/api/iac_router.py` (243 LOC) — IaC scanning API
- Scanner ingest accepts IaC findings from external tools

**Gap to close**: IaC router is thin. Need built-in rule engine for common misconfigurations, not just ingestion from external tools.

**Action**:
- Enhance `iac_router.py`: `POST /api/v1/iac/scan` → accept Terraform/CloudFormation/K8s YAML and run built-in rule checks
- Add `GET /api/v1/iac/rules` → list detection rules (e.g., "S3 bucket public access", "Security group allows 0.0.0.0/0", "Container runs as root")
- Add `POST /api/v1/iac/scan-repo` → clone a repo and scan all IaC files
- Add `GET /api/v1/iac/findings` → list all IaC misconfigurations with fix suggestions
- Add `POST /api/v1/iac/fix` → auto-remediate common IaC misconfigurations
- API depth target: 8+ endpoints covering scan, rules, findings, fix, supported formats

### Domain 11: Developer Experience

**Apiiro has**: Developer risk scoring, security champion identification, developer-friendly remediation in PR context.

**Aikido has**: VSCode plugin, IDE findings display, developer-friendly explanations, CI/CD integration, Slack notifications.

**ALdeci has**:
- `suite-integrations/api/ide_router.py` (982 LOC) — IDE integration with finding display
- `suite-core/core/developer_risk_profiler.py` (913 LOC) — Developer behavior scoring
- Developer risk profiles router

**Gap to close**: IDE router is comprehensive but needs real IDE plugin. Developer profiles exist but aren't wired to the UI Developer Dashboard.

**Action**:
- Ensure `ide_router.py` endpoints work end-to-end: `GET /api/v1/ide/findings` returns real findings for the current file/project
- Wire developer_risk_profiler to UI: `GET /api/v1/developer-profiles` → list all developers with risk scores, `GET /api/v1/developer-profiles/{dev_id}` → detailed profile
- Add `GET /api/v1/developer-profiles/champions` → identify security champions (low-risk developers who fix vulnerabilities)
- Add `POST /api/v1/developer-profiles/score` → compute risk score for a developer based on their recent commits
- Wire to connectors (GitHub/GitLab) to pull real commit history for profiling
- API depth target: 12+ endpoints covering profiles, scoring, champions, training, IDE integration

### Domain 12: Runtime Protection (Strategic Differentiator Opportunity)

**Apiiro has**: No runtime protection (they're pre-production focused).

**Aikido has**: Zen — application firewall for Node.js/Python/Java, bot protection, zero-day blocking, rate limiting, IP blocking, country blocking.

**ALdeci has**: Nothing in runtime protection currently.

**Gap to close**: This is a significant gap vs Aikido. ALdeci can't protect apps at runtime.

**Action (Lower Priority — Flag for Future)**:
- For now, add `GET /api/v1/runtime/status` → placeholder that shows runtime protection is "planned"
- Focus on pre-production depth first (Domains 1-11) — that's where we beat Apiiro
- In the UI, add a "Runtime Protection" section in the Protect space showing the vision but clearly labeled as "Coming in v2"
- Do NOT build a full WAF — that's a separate product. Focus on runtime context (which containers are running our vulnerable code?)

---

## End-to-End Wiring: API → Engine → CLI → UI

**This is critical.** Every feature must work end-to-end, not just have an API that returns data. For each domain above, verify the full chain:

```
UI Component → API Call → Router Endpoint → Engine/Service → Database/External API → Response → UI Update
```

**Explicit wiring map:**

| UI Page | API Endpoint | Backend Engine | CLI Command |
|---------|-------------|----------------|-------------|
| Mission Control Dashboard | `GET /api/v1/analytics/dashboard` | `brain_pipeline.py` → `fail_engine.py` | `fixops status` |
| Finding Explorer | `GET /api/v1/findings` | `normalizers.py` → `PersistentDict` | `fixops findings list` |
| AI Triage Queue | `POST /api/v1/triage/unified` | `brain_pipeline.py` step 8 | `fixops triage` |
| SBOM Inventory | `POST /api/v1/sbom/analyze` | `normalizers.py` → `dependency_graph.py` | `fixops sbom analyze` |
| AutoFix Center | `POST /api/v1/autofix/suggest` | `autofix_engine.py` | `fixops autofix` |
| Scanner Control | `POST /api/v1/scanner-ingest/upload` | `scanner_ingest_router.py` → scanners | `fixops scan` |
| Evidence Bundles | `POST /api/v1/evidence/bundles` | `crypto.py` → RSA signing | `fixops evidence create` |
| Compliance Dashboard | `GET /api/v1/compliance/status` | `compliance_engine.py` | `fixops compliance check` |
| Developer Profiles | `GET /api/v1/developer-profiles` | `developer_risk_profiler.py` | `fixops developers list` |
| Knowledge Graph | `GET /api/v1/knowledge-graph/query` | `knowledge_graph.py` → NetworkX | `fixops graph query` |
| MPTE Testing | `POST /api/v1/mpte/requests` | `micro_pentest.py` → `mpte_advanced.py` | `fixops pentest run` |
| Integration Settings | `GET /api/v1/integrations/status` | `connectors.py` | `fixops integrations list` |

**For each row above:**
1. Read the UI page component
2. Verify the API endpoint exists and returns real data
3. Verify the engine is called (not a stub)
4. Verify the CLI command triggers the same engine
5. Wire any disconnected pieces

---

## 25 Personas (Each Must Have a Working Workflow)

Don't think in features — think in user journeys. Each persona below must be able to complete their primary workflow end-to-end:

| # | Persona | Primary Workflow | Key API Endpoints |
|---|---------|-----------------|-------------------|
| 1 | CISO | View risk posture, approve priorities, generate board report | `/brain/pipeline`, `/reports/generate`, `/analytics/trends` |
| 2 | VP Engineering | See team security debt, developer risk profiles | `/developer-profiles`, `/analytics/team-metrics` |
| 3 | Security Architect | Model threats, map attack surface, review architecture risks | `/knowledge-graph`, `/attack-surface`, `/mpte/requests` |
| 4 | AppSec Engineer | Triage findings, verify exploitability, assign remediation | `/triage/unified`, `/mpte/requests`, `/autofix/suggest` |
| 5 | DevSecOps Engineer | Configure CI/CD gates, manage scanner policies | `/scanner-ingest`, `/policies`, `/ci-cd/integration` |
| 6 | SOC Analyst | Monitor alerts, export to SIEM, correlate threats | `/findings/export/cef`, `/findings/export/syslog`, `/feeds` |
| 7 | Compliance Officer | Check framework coverage, collect evidence, prep audit | `/compliance/status`, `/evidence/collect`, `/reports/compliance` |
| 8 | Risk Manager | Quantify risk, track SLAs, manage risk acceptance | `/risk/score`, `/sla/tracking`, `/risk/acceptance` |
| 9 | Developer | See findings in IDE, get auto-fix suggestions | `/ide/findings`, `/autofix/suggest`, `/developer-profiles` |
| 10 | Engineering Manager | Sprint security metrics, team comparison | `/analytics/sprint`, `/developer-profiles/team` |
| 11 | Cloud Security Engineer | Cloud posture, IaC scanning, CNAPP findings | `/iac/scan`, `/cloud-posture`, `/cnapp/findings` |
| 12 | Penetration Tester | Run micro-pentests, review PoC evidence | `/mpte/requests`, `/mpte/results`, `/micro-pentest` |
| 13 | GRC Analyst | Manage policies, map controls, monitor compliance | `/policies`, `/compliance/controls`, `/compliance/status` |
| 14 | Incident Responder | Correlate vulns to incidents, assess blast radius | `/knowledge-graph/blast-radius`, `/findings/correlate` |
| 15 | Product Security Lead | Application inventory, risk-ranked backlog | `/applications`, `/triage/unified`, `/risk/ranked` |
| 16 | IT Auditor | Verify evidence signatures, review audit trail | `/evidence/verify`, `/audit/trail`, `/evidence/bundles` |
| 17 | Release Manager | Security gate status, release readiness | `/ci-cd/gates`, `/system/readiness`, `/risk/release` |
| 18 | Vendor Risk Analyst | SBOM analysis, third-party risk scoring | `/sbom/analyze`, `/supply-chain/risk`, `/feeds/osv` |
| 19 | Data Protection Officer | PII exposure, data flow mapping, privacy | `/findings?type=pii`, `/data-flow`, `/compliance/privacy` |
| 20 | SecOps Manager | Team workload, automation ROI, alert fatigue metrics | `/analytics/workload`, `/automation/metrics` |
| 21 | Chief Risk Officer | Enterprise risk aggregation, regulatory exposure | `/risk/enterprise`, `/compliance/regulatory`, `/reports/executive` |
| 22 | Platform Engineer | API health, integration status, system config | `/health`, `/system/readiness`, `/integrations/status` |
| 23 | Security Trainer | Knowledge base, vulnerability patterns, training | `/knowledge-graph/patterns`, `/training/modules` |
| 24 | Board Member | One-page risk summary, trends, benchmarks | `/reports/board-summary`, `/analytics/trends` |
| 25 | External Auditor | Read-only evidence, framework views, exports | `/evidence/bundles`, `/compliance/export`, `/reports` |

---

## Competitive Advantage Matrix (Beat These Numbers)

| Capability | Apiiro | Aikido | ALdeci Target |
|-----------|--------|--------|---------------|
| Scanner types | 3-4 (SCA, secrets, IaC, code) | 8+ (SAST, SCA, secrets, IaC, container, CSPM, DAST, malware) | **15+** (8 native + 10 connectors + MPTE) |
| Languages supported | 20+ | 20+ | **25+** (via Semgrep rules + native scanners) |
| Compliance frameworks | 3 (PCI, NIST, SOC2) | 4 (PCI, SOC2, ISO27001, HIPAA) | **6+** (PCI v4, NIST, SOC2, ISO27001, HIPAA, OWASP ASVS) |
| Fix generation | AutoFix Agent | Auto-PR | **LLM-powered + Offline templates + PR generation** |
| Noise reduction | "Significant" | "95%" | **98%** (multi-LLM consensus + MPTE verification) |
| Evidence tamper-proof | No | No | **Yes** (RSA-SHA256 + ML-DSA post-quantum signing) |
| Exploit verification | No | AI pentesting | **MPTE 19-phase micro-pentest engine** |
| Air-gapped deployment | Partial | Partial | **Full** (all scanners + LLM fallback work offline) |
| CI/CD platforms | GitHub, GitLab, Azure | GitHub, GitLab, Bitbucket, Azure | **5+** (GitHub, GitLab, Azure, Bitbucket, Jenkins) |
| Integrations | 15+ | 20+ | **17+** (7 platform + 10 security tool connectors) |
| Runtime protection | No | Zen firewall | **Planned v2** (honest — don't fake this) |
| MCP/AI-native | No | No | **Yes** (771 MCP-accessible endpoints) |

---

## Execution Rules

1. **Read before writing.** Always read the existing component/router before modifying. Understand the data model.

2. **One space at a time.** Complete Mission Control fully before moving to Discover. Complete Discover before Prioritize. Follow the CTEM flow.

3. **Wire real APIs — never add mock data.** If an endpoint returns empty results, that's fine. Show an empty state. Never inject fake numbers to make a demo look good.

4. **Test after every change.** Run `python -m pytest tests/ --timeout=10 -x -q` frequently. Don't accumulate breakage.

5. **Fix the product code, not just the tests.** If a test expects behavior the product doesn't implement, implement the behavior (or update the test if the behavior is intentionally different). Never disable tests to hide problems.

6. **Every API endpoint must:**
   - Return real computed data (not stubs)
   - Handle errors with consistent JSON structure `{"detail": "...", "status_code": N}`
   - Validate input (Pydantic models)
   - Support pagination where lists are returned (`?page=1&per_page=20`)
   - Include `org_id` tenant isolation
   - Log operations via structlog

7. **Every UI component must:**
   - Fetch data from real API on mount/interaction using `src/lib/api.ts`
   - Show loading skeleton during fetch
   - Show error state with retry button on failure
   - Show empty state with guidance when no data
   - Update immediately after mutations (optimistic or refetch)

8. **Never break working features.** The test suite is the safety net. If tests fail after your changes, fix your changes, not the tests (unless the test was genuinely wrong).

9. **Depth over breadth.** A single domain fully working end-to-end (API → Engine → CLI → UI) is worth more than 5 domains with stub APIs.

10. **Be honest about what's real.** If a feature requires external services (LLM, cloud providers, MPTE server), clearly document the requirement. Show "Configure API key to enable" instead of faking output.

## Definition of Done

Stop when ALL of these are true:

- [ ] Every screen in all 5 Workflow Spaces shows real data from real API calls
- [ ] Every button triggers a real action with loading/success/error feedback
- [ ] Every form validates, submits, and reflects changes
- [ ] Navigation flows naturally across all persona workflows
- [ ] Full test suite passes (7,500+ tests, 0 failures)
- [ ] App starts cleanly with 1,029+ routes
- [ ] OpenAPI spec generates without errors (930+ paths)
- [ ] A walkthrough of CISO -> AppSec -> Developer -> Auditor workflow works end-to-end
- [ ] No "Coming Soon", no hardcoded data, no dead-end pages
- [ ] Every integration connector shows real connection status
- [ ] Evidence bundles generate with valid RSA-SHA256 signatures
- [ ] Compliance dashboard shows real framework coverage from actual assessments
- [ ] All 12 competitive domains have API depth >= targets listed above
- [ ] Every CLI command maps to an API endpoint that maps to a UI page
- [ ] Risk Graph is queryable and renders in UI
- [ ] SBOM analysis returns real dependency graph with reachability
- [ ] AutoFix generates real code patches (LLM or templates)
- [ ] CI/CD gates evaluate findings against configurable policies

## Start Here

1. Run `cd suite-ui/aldeci-ui-new && cat src/App.tsx` to understand the routing structure
2. Run `ls src/pages/` to see all page directories
3. For each page, read the component and identify what data it displays
4. Cross-reference with `grep -r "api/v1" src/` to find existing API calls
5. Start wiring Mission Control's Command Dashboard to real endpoints
6. Work through each space systematically
7. After each space is wired, audit the corresponding domains from the Competitive Gap Analysis
8. Enhance API depth in each domain to match or exceed targets

Remember: **You are building a product that enterprises will pay $100K+/year for.** Every screen, every interaction, every response must feel like it was built by a team of 20, not generated by AI. Quality over quantity. Depth over breadth. Working over pretty.
