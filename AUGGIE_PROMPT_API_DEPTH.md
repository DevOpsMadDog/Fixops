# ALdeci CTEM+ — Augment AI (Auggie) API Depth & Competitive Parity Prompt

> Paste this into Auggie. Optimized for Claude 4.6 — structured for chain-of-thought reasoning, explicit constraints, and measurable exit criteria.
> **Companion to**: `AUGGIE_PROMPT.md` (UI/UX wiring prompt)

---

You are acting as **Principal Backend Engineer and Competitive Intelligence Lead** for ALdeci, a CTEM+ Decision Intelligence Platform for Application Security. Your job is to audit every API endpoint and core engine for depth, wire disconnected components end-to-end, and ensure ALdeci's backend functionality is **demonstrably superior** to Apiiro and Aikido.

## Your Mission

The UI prompt (`AUGGIE_PROMPT.md`) handles screen wiring. THIS prompt handles **API depth** — ensuring every endpoint returns real, computed data with enterprise-grade functionality. The goal: when a prospect compares ALdeci's API output against Apiiro or Aikido, ALdeci wins on depth, accuracy, and completeness.

---

## System Architecture (Read First)

```
Monolith: 6 Python suites on one FastAPI app (port 8000), 1,029 API routes

suite-api/          → FastAPI gateway, 34 router mounts, JWT + API key auth
suite-core/         → Brain pipeline, FAIL scoring, knowledge graph, scanners, CLI (140K LOC)
suite-attack/       → MPTE micro-pentest, DAST, CSPM, SAST, container, secrets, malware
suite-feeds/        → NVD, KEV, EPSS, OSV, ExploitDB threat intel
suite-evidence-risk/ → Evidence bundles, risk scoring, compliance, reachability (6,265 LOC)
suite-integrations/ → Jira, Confluence, Slack, ServiceNow, GitHub, GitLab, Azure DevOps, MCP, IaC, webhooks

Entry point:  suite-api/apps/api/app.py (create_app factory, 2,893 LOC)
Import mechanism: sitecustomize.py auto-prepends all suite dirs to sys.path
Database: SQLite WAL (56 .db files, PersistentDict pattern)
CLI: suite-core/core/cli.py (5,929 LOC, 34 commands, argparse-based)
Tests: 7,500+ passing, pytest with 10s timeout
```

---

## Competitive Intelligence — Feature-by-Feature

Before writing ANY code, understand where ALdeci stands against each competitor. Research their official docs at:
- **Apiiro**: https://docs.apiiro.com / https://apiiro.com/platform/
- **Aikido**: https://docs.aikido.dev / https://www.aikido.dev/

### Feature Comparison Matrix

| Feature | Apiiro | Aikido | ALdeci Status | ALdeci Grade | Action Required |
|---------|--------|--------|---------------|--------------|-----------------|
| **Code-to-Cloud Risk** | CORE FEATURE (design-time risk) | Basic | `code_to_cloud_tracer.py` exists, no UI/CLI | **D** | Wire to API + UI, add commit-level risk tracking |
| **Reachability Analysis** | CORE FEATURE (call graph + data flow) | No | 6,265 LOC, real Python AST, JS/Java are stubs | **B-** | Fix JS/Java parsers, add cross-module resolution |
| **SBOM + Runtime Correlation** | Static SBOM only | Runtime only | `sbom_runtime_correlator.py` (693 LOC) — UNIQUE | **A-** | Add transitive dep resolution, VEX support |
| **Developer Risk Profiles** | CORE FEATURE (commit patterns) | No | `developer_risk_profiles_router.py` (913 LOC) | **B+** | Add commit frequency, PR review patterns |
| **Material Change Detection** | CORE FEATURE | No | `material_change_detector.py` exists | **C+** | Audit depth, wire to pipeline |
| **Auto-Triage (Noise Reduction)** | Good | Claims 95% reduction | Brain pipeline 12-step with EPSS/KEV | **B+** | Add false positive feedback loop |
| **Container Scanning** | Via integrations | Native (Trivy-based) | `container_scanner.py` (445 LOC, Trivy + Dockerfile rules) | **B-** | Add K8s manifest scanning, runtime inventory |
| **Cloud Posture (CSPM)** | Not a focus | Basic | `cspm_engine.py` (609 LOC) — only 20 rules, NO live API | **D+** | Add live AWS/Azure/GCP scanning, 100+ rules |
| **DAST Scanning** | Not a focus | Native | `dast_engine.py` (633 LOC) + `real_scanner.py` (3,055 LOC) | **B** | Add authenticated crawling, session handling |
| **Secret Scanning** | Via integrations | Native (Gitleaks) | `secrets_scanner.py` (848 LOC, Gitleaks + TruffleHog + built-in) | **A-** | Add live secret verification |
| **IaC Scanning** | Not a focus | Native (Checkov) | `iac_scanner.py` (713 LOC, Checkov + TFSec) | **B** | Add Bicep, Pulumi support |
| **API Security** | Not a focus | Native | `api_fuzzer.py` (361 LOC, real HTTP fuzzing) | **B-** | Add BOLA/IDOR detection, GraphQL fuzzing |
| **License Compliance** | Not a focus | Basic | `license_compliance.py` (241 LOC) — only 8 licenses | **D** | Expand to 50+ licenses, SPDX expression parsing |
| **Supply Chain Analysis** | Deep (SBOM + deps) | Basic | Distributed across 4 modules | **C** | Add typosquatting detection, SLSA provenance |
| **CI/CD Pipeline Gates** | Native | One-click GitHub Action | Adapters exist, no gate endpoint | **C-** | Create `/api/v1/gate` pass/fail endpoint |
| **Micro-Pentest Verification** | NONE | NONE | `micro_pentest.py` (2,054 LOC) — UNIQUE | **A** | Already a differentiator |
| **Multi-LLM Consensus** | NONE | NONE | 6 LLM providers + deterministic fallback — UNIQUE | **A** | Already a differentiator |
| **Cryptographic Evidence** | NONE | NONE | `crypto.py` (582 LOC) RSA-SHA256 — UNIQUE | **A** | Already a differentiator |
| **MCP (AI Agent Protocol)** | NONE | NONE | `mcp_server.py` (2,421 LOC) — UNIQUE | **A** | Already a differentiator |
| **Integration Connectors** | Deep (DevOps focus) | Light (CI focus) | 17 real HTTP connectors with retry/circuit breaker | **A-** | All production-grade |
| **Compliance Frameworks** | Not a focus | Not a focus | 6 frameworks (SOC2, PCI-DSS 4.0, ISO 27001, NIST 800-53, NIST CSF, OWASP ASVS) | **B** | Add HIPAA, FedRAMP |
| **SIEM Export** | Via API | Not a focus | CEF format file export only | **C** | Add syslog push, Splunk HEC, Sentinel |

---

## Priority Fixes by Competitive Impact

### TIER 1: Close Critical Gaps (Apiiro Parity)

#### 1.1 Reachability Analysis — Fix JS/Java Parsers (Currently Stubs)

**Why this matters**: Apiiro's #1 differentiator is "design-time risk assessment" powered by code-level reachability. ALdeci has 6,265 LOC of reachability code but JS/Java use regex instead of proper AST parsing.

**Current state** (15 files in `suite-evidence-risk/risk/reachability/`):
- `proprietary_analyzer.py` (964 LOC) — Python AST is REAL (full call graph, taint analysis)
- `call_graph.py` (213 LOC) — Python AST-based call graph builder
- `data_flow.py` (149 LOC) — Source-to-sink analysis
- `code_analysis.py` (553 LOC) — CodeQL/Semgrep/Bandit integration scaffold
- JS/Java analysis in `proprietary_analyzer.py` uses regex `function\s+(\w+)` — NOT real parsing

**Fix**:
1. For JavaScript: Use `tree-sitter-javascript` (pip installable) or write a proper regex-based parser that handles arrow functions, methods, imports/exports
2. For Java: Parse method declarations properly (`public|private|protected ... methodName(`)
3. Add cross-module resolution: when function A calls function B in a different file, follow the import
4. Wire to brain pipeline step 6 (currently uses simplified reachability)
5. Add API endpoints: `POST /api/v1/reachability/analyze` should return call graph + taint paths

**Files**: `suite-evidence-risk/risk/reachability/proprietary_analyzer.py`, `call_graph.py`, `code_analysis.py`
**Competitive target**: Match Apiiro's "is this vulnerability reachable from an entry point?" analysis

#### 1.2 Code-to-Cloud Tracing — Wire Existing Module

**Why this matters**: Apiiro's core value prop is "understand risk from code to cloud." ALdeci has `code_to_cloud_tracer.py` but it's not wired to any API, CLI, or UI.

**Fix**:
1. Read `suite-core/core/code_to_cloud_tracer.py` — understand what it does
2. Create router: `suite-core/api/code_to_cloud_router.py` with endpoints:
   - `POST /api/v1/code-to-cloud/trace` — trace a finding from code commit to cloud deployment
   - `GET /api/v1/code-to-cloud/map/{app_id}` — get the code-to-cloud map for an application
   - `GET /api/v1/code-to-cloud/risk/{commit_sha}` — risk assessment for a specific commit
3. Add CLI command: `code-to-cloud trace --finding-id <id>` and `code-to-cloud map --app <app_id>`
4. Wire to brain pipeline as an enrichment step

**Competitive target**: Match Apiiro's code-to-cloud context correlation

#### 1.3 Material Change Detection — Audit and Deepen

**Why this matters**: Apiiro detects "material changes" (security-relevant code changes vs. cosmetic ones). ALdeci has the module but depth is unknown.

**Fix**:
1. Read `suite-core/core/material_change_detector.py` — audit what it actually does
2. Ensure it categorizes changes as: security-relevant, dependency update, config change, cosmetic
3. Wire to developer risk profiles (material changes should affect developer risk scores)
4. Add API endpoint: `POST /api/v1/changes/analyze` should accept a diff and return materiality classification
5. Add to brain pipeline: material change detection should influence triage priority

**Competitive target**: Match Apiiro's material change detection for noise reduction

### TIER 2: Close Critical Gaps (Aikido Parity)

#### 2.1 CI/CD Pipeline Gate Endpoint

**Why this matters**: Aikido's onboarding is "one-click GitHub Action." ALdeci has CI adapters (Jenkins, SonarQube, GitHub) but no standard gate endpoint.

**Current state**:
- `suite-integrations/integrations/github/adapter.py` (105 LOC) — payload processor, NOT a gate
- `suite-integrations/integrations/jenkins/adapter.py` (82 LOC) — payload processor
- No `POST /api/v1/gate` endpoint exists

**Fix**:
1. Create `suite-api/apps/api/gate_router.py`:
   ```python
   @router.post("/check")  # POST /api/v1/gate/check
   async def check_gate(payload: GateCheckRequest):
       """Binary pass/fail for CI/CD pipelines.
       Accepts SARIF/SBOM/findings, runs through DecisionEngine,
       returns {pass: bool, reason: str, findings_count: int, policy_violations: []}
       """
   ```
2. Create GitHub Action YAML template at `suite-integrations/templates/github-action.yml`
3. Create GitLab CI template at `suite-integrations/templates/gitlab-ci.yml`
4. Add CLI command: `gate check --sarif <file> --policy <policy_id>` that calls the API

**Competitive target**: Match Aikido's "one-click CI/CD integration" experience

#### 2.2 License Compliance — Expand from 8 to 50+ Licenses

**Current state**: `suite-evidence-risk/risk/license_compliance.py` (241 LOC) — only 8 licenses (MIT, Apache 2.0, BSD-3, GPL-2, GPL-3, AGPL-3, LGPL-2.1, MPL-2.0). No SPDX expression parsing.

**Fix**:
1. Expand license database to 50+ common licenses (ISC, Unlicense, CC-BY-*, EUPL, Artistic, Zlib, WTFPL, 0BSD, BSL-1.0, etc.)
2. Add SPDX license expression parsing: handle `MIT OR Apache-2.0`, `GPL-3.0-only WITH Classpath-exception-2.0`
3. Add license detection from source files (scan LICENSE, COPYING, package.json `license` field)
4. Add transitive license analysis (if dep A uses GPL-3.0, and dep B uses dep A, dep B has GPL-3.0 obligation)
5. Wire to SBOM generator — every generated SBOM should include license data

**Files**: `suite-evidence-risk/risk/license_compliance.py`
**Competitive target**: Match FOSSA/Snyk-level license analysis

#### 2.3 CSPM — Add Live Cloud API Scanning

**Current state**: `suite-core/core/cspm_engine.py` (609 LOC) — only config-file analysis with 20 rules (10 AWS, 5 Azure, 5 GCP). Detects boto3/azure SDK but never uses them.

**Fix**:
1. Implement `scan_aws_live()` using boto3:
   - S3 bucket public access (`get_bucket_acl`, `get_public_access_block`)
   - Security groups with 0.0.0.0/0 (`describe_security_groups`)
   - IAM users without MFA (`list_users`, `list_mfa_devices`)
   - CloudTrail logging status (`describe_trails`)
   - EBS encryption defaults (`get_ebs_encryption_by_default`)
2. Implement `scan_azure_live()` using azure SDK:
   - Storage account public access
   - NSG rules
   - Key Vault access policies
3. Expand config rules from 20 to 100+ (add CIS Benchmark Level 1 + 2 rules)
4. Add API endpoints for live scanning: `POST /api/v1/cspm/scan/live` (requires cloud credentials)
5. Add Kubernetes manifest scanning (Deployment, Pod, Service YAML analysis)

**Files**: `suite-core/core/cspm_engine.py`, `suite-attack/api/cspm_router.py`
**Competitive target**: Basic CNAPP functionality (Wiz-light)

#### 2.4 Container Scanning — Add K8s Manifest Analysis

**Current state**: `suite-core/core/container_scanner.py` (445 LOC) — Dockerfile rules + Trivy integration. No Kubernetes support.

**Fix**:
1. Add K8s manifest scanning (YAML with `apiVersion`+`kind`):
   - Privileged containers (`securityContext.privileged: true`)
   - Root user (`runAsNonRoot: false`)
   - Missing resource limits
   - hostNetwork/hostPID/hostIPC
   - Missing readOnlyRootFilesystem
   - Service account auto-mount
2. Add Helm chart scanning (parse `values.yaml` + templates)
3. Implement Grype scanning (binary detected but not used)
4. Add image layer analysis (beyond Trivy's output, add secret detection in layers)

**Files**: `suite-core/core/container_scanner.py`
**Competitive target**: Match Aikido's container + K8s scanning

### TIER 3: Deepen Existing Strengths (Widen the Moat)

#### 3.1 SBOM — Add Transitive Dependencies and VEX

**Current state**: `sbom_runtime_correlator.py` (693 LOC) + `generator.py` (655 LOC) — parses 8 lockfile formats, correlates SBOM with runtime. UNIQUE to ALdeci.

**Fix**:
1. Add transitive dependency resolution:
   - For npm: parse `package-lock.json` v3 `packages` tree (includes nested deps)
   - For pip: use `pip-compile`-style resolution or parse `pip freeze` output
   - For Maven: parse `mvn dependency:tree` XML output
2. Add VEX (Vulnerability Exploitability eXchange) support:
   - Parse OpenVEX documents
   - Apply VEX status (exploitable, not_affected, under_investigation) to findings
   - Generate VEX documents from ALdeci's own reachability analysis
3. Add vulnerability database cross-reference within correlator (NVD/OSV lookup for each component)
4. Add dependency graph visualization data (return edges for UI rendering)

**Files**: `suite-evidence-risk/risk/sbom/generator.py`, `suite-core/core/sbom_runtime_correlator.py`

#### 3.2 Brain Pipeline — Add False Positive Feedback Loop

**Current state**: `brain_pipeline.py` (1,878 LOC, 12 steps) — real EPSS/KEV enrichment, FAIL scoring. No feedback mechanism.

**Fix**:
1. Add feedback endpoint: `POST /api/v1/brain/feedback` with `{finding_id, is_false_positive: bool, reason: str}`
2. Store feedback in SQLite
3. In brain pipeline step 3 (triage), check feedback history:
   - If similar findings were marked false positive 3+ times, auto-suppress
   - Track FP rate per scanner, per CWE, per application
4. Add CLI command: `brain feedback --finding-id <id> --false-positive --reason "..."
5. Expose FP rate analytics: `GET /api/v1/analytics/false-positive-rate`

**Competitive target**: Match Aikido's "95% noise reduction" claim with measurable FP metrics

#### 3.3 DAST — Add Authenticated Scanning

**Current state**: `dast_engine.py` (633 LOC) — real HTTP DAST with SQLi, XSS, path traversal, SSRF, but NO authentication support.

**Fix**:
1. Add authentication modes:
   - Bearer token (header injection)
   - Cookie-based (login form submission + session tracking)
   - Basic auth
   - API key (header/query param)
2. Add `session_config` parameter to DAST scan:
   ```python
   session_config = {
       "auth_type": "form",
       "login_url": "https://target.com/login",
       "credentials": {"username": "test", "password": "test"},
       "success_indicator": "dashboard"  # string in response that confirms login
   }
   ```
3. Maintain cookies across crawl/test phases
4. Add API-specific DAST: parse OpenAPI spec, fuzz each endpoint with proper auth

**Files**: `suite-core/core/dast_engine.py`

#### 3.4 Supply Chain — Add Typosquatting and Provenance

**Current state**: Distributed across 4 modules. No dedicated supply chain engine.

**Fix**:
1. Create `suite-core/core/supply_chain_engine.py`:
   - Typosquatting detection: compare package names against known packages using Levenshtein distance
   - Provenance verification: check npm provenance attestations, PyPI attestations
   - Package age/popularity scoring: flag packages < 30 days old with < 100 downloads
   - Maintainer analysis: flag packages with single maintainer, recent ownership transfer
2. Add API: `POST /api/v1/supply-chain/analyze` (accepts SBOM, returns risk-scored dependencies)
3. Add CLI: `supply-chain analyze --sbom <file>`

#### 3.5 SIEM Integration — Add Push Capabilities

**Current state**: CEF format file export at `/api/v1/audit/logs/export?format=siem`. No push.

**Fix**:
1. Add syslog forwarding: `POST /api/v1/siem/configure` with `{type: "syslog", host: "...", port: 514, protocol: "tcp|udp"}`
2. Add Splunk HEC integration: `POST /api/v1/siem/configure` with `{type: "splunk_hec", url: "...", token: "..."}`
3. Add real-time event streaming via existing SSE infrastructure (`/api/v1/stream/events`)
4. CEF, LEEF, and JSON output formats

**Files**: `suite-api/apps/api/audit_router.py`, NEW `suite-integrations/api/siem_router.py`

---

## CLI-to-API-to-UI Wiring Map (Fix Disconnections)

### Critical Disconnections to Fix

| Problem | Impact | Fix |
|---------|--------|-----|
| CLI `analytics` commands return **stub data** | CLI users get fake numbers | Wire to real analytics engine (SLA metrics, brain pipeline stats) |
| CLI `advanced-pentest` commands return **stub data** | CLI users get fake pentest results | Wire to real MPTE engine (`micro_pentest.py`) |
| CLI `reachability` commands return **stub data** | CLI users get fake reachability | Wire to real reachability engine (`suite-evidence-risk/risk/reachability/`) |
| CLI and API use **different databases** for teams/users/compliance/reports/inventory/policies | Data inconsistency between CLI and API | CLI should call the same core functions as API routers, not direct SQLite |
| 13 API router groups have **no UI or CLI consumers** | Dead endpoints confuse auditors | Wire to UI or remove if redundant |
| `train-forecast`, `train-bn-lr`, `predict-bn-lr`, `backtest-bn-lr` have **no API** | ML features only accessible via CLI | Add `/api/v1/ml/train`, `/api/v1/ml/predict` endpoints |

### Orphaned API Routers (No UI, No CLI)

These routers are mounted and working but called by NOTHING. Either wire them or remove them:

| Router | Endpoints | Recommendation |
|--------|-----------|----------------|
| `/api/v1/ide/*` | IDE integration (status, config, analyze, suggestions, SARIF) | Wire to VS Code extension docs, keep as-is |
| `/api/v1/triage/*` | Triage queue, enrichment, feedback, stats | Wire to UI's Prioritize space |
| `/api/v1/vulns/*` | Vulnerability discovery, contributions | Merge into findings/discovery |
| `/api/v1/api-fuzzer/*` | API fuzzing discover/fuzz | Wire to Discover > API Security page |
| `/api/v1/dast/*` | DAST scanning | Wire to Discover > DAST Scanning page |
| `/api/v1/malware/*` | Malware detection scan | Wire to Discover > Malware Detection page |
| `/api/v1/connectors/*` | Connector registration/testing | Merge with `/api/v1/integrations/*` or remove |
| `/api/v1/webhook-subscriptions/*` | Webhook subscription CRUD | Wire to Settings > Webhooks page |
| `/api/v1/webhooks/*` | Inbound webhooks, drift, outbox | Wire to Settings > Webhooks page |
| `/provenance/*` | SLSA provenance chains | Wire to Prove > Evidence page |
| `/risk/*` | Risk scores and overview | Wire to Prioritize > Risk Dashboard |

### Core Engine Functions Never Exposed

These powerful engines are buried with no API or CLI access:

| Engine | File | Recommendation |
|--------|------|----------------|
| Causal inference | `core/causal_inference.py` | Add `/api/v1/analytics/causal` — "what caused this risk increase?" |
| GNN attack graph | `core/attack_graph_gnn.py` | Add `/api/v1/attack-paths/gnn` — graph neural network attack prediction |
| Monte Carlo simulation | `core/monte_carlo.py` | Add `/api/v1/risk/simulate` — stochastic risk modeling |
| SOC2 evidence generator | `core/soc2_evidence_generator.py` | Wire to compliance evidence endpoints |
| Vector store | `core/services/vector_store.py` | Wire to semantic search / similarity queries |
| Explainability (SHAP) | `core/services/enterprise/explainability.py` | Wire to `/api/v1/brain/explain/{finding_id}` |
| Vulnerability intelligence | `core/vuln_intelligence.py` | Wire to feeds enrichment pipeline |

---

## Integration Depth Audit (All 17 Connectors Are Real)

Every connector in `connectors.py` (3,029 LOC) and `security_connectors.py` (1,815 LOC) uses real HTTP clients with `requests.Session`, retry (urllib3.Retry, 3 retries, exponential backoff), circuit breakers (open after 5 failures), rate limiting, and connection pooling. **None are stubs.**

### Connector Enhancement Priorities

| Connector | Current State | Enhancement |
|-----------|--------------|-------------|
| **Jira** (512 LOC) | Full CRUD + transitions | Add JQL bulk query, custom field support, sprint assignment |
| **GitHub** (423 LOC) | Issue CRUD + PR comments | Add check run creation for CI/CD gate, code scanning alert management |
| **Slack** (75 LOC) | Incoming webhooks only | Add Block Kit formatting, interactive messages, channel listing via Slack API |
| **AWS Security Hub** (86 LOC) | Get/update findings | Add batch import for ALdeci findings INTO Security Hub |
| **Wiz** (161 LOC) | GraphQL queries, real OAuth2 | Add Wiz Issue creation, remediation ticket sync |
| **Webhook System** (1,922 LOC) | Bidirectional sync, HMAC signatures | Add delivery retry dashboard, dead letter queue visibility |

### Missing Connector: No Pipeline Gate Binary Endpoint

**Critical gap**: There is no `POST /api/v1/gate/check` that returns `{pass: true/false}`. CI/CD systems need this. The adapters (Jenkins, SonarQube, GitHub) process inbound payloads but don't provide the gate verdict pattern that CI systems poll.

---

## Scanner Depth Summary

| Scanner | LOC | Real Logic? | Grade | Key Enhancement |
|---------|-----|-------------|-------|-----------------|
| DAST engine | 3,688 | YES (real HTTP payloads: SQLi, XSS, SSRF, SSTI, smuggling) | **B** | Add authenticated scanning |
| Secret scanner | 1,200 | YES (Gitleaks + TruffleHog + 18 built-in regex) | **A-** | Add live verification |
| Container scanner | 445 | YES (Dockerfile rules + Trivy) | **B-** | Add K8s + Grype |
| IaC scanner | 713 | YES (Checkov + TFSec, 6 frameworks detected) | **B** | Add Bicep, Pulumi |
| CSPM engine | 609 | PARTIAL (config files only, 20 rules) | **D+** | Add live cloud API scanning |
| API fuzzer | 361 | YES (real HTTP fuzzing from OpenAPI specs) | **B-** | Add BOLA, GraphQL |
| SAST engine | ~800 | YES (regex + external tool integration) | **B** | Add inter-procedural analysis |
| License analyzer | 241 | YES but only 8 licenses | **D** | Expand to 50+ |
| SBOM correlator | 1,348 | YES (3-tier matching, Levenshtein fuzzy) | **A-** | Add transitive deps |
| Reachability | 6,265 | YES for Python, stubs for JS/Java | **B-** | Fix multi-language support |

---

## Execution Rules

1. **Read existing code before writing.** Every file mentioned above exists. Read it. Understand the data model. Don't duplicate what's there.

2. **Research competitors before building.** For each feature enhancement, check how Apiiro/Aikido implement it. Match or exceed their approach.

3. **Wire real engines — never add stubs.** If the reachability engine returns empty results for a language, show "Analysis not available for {language}" — don't fake it.

4. **Fix disconnections first, then deepen.** Wiring existing engines to API/CLI/UI has higher ROI than building new features.

5. **Test after every change.** Run `python -m pytest tests/ --timeout=10 -x -q`. Don't accumulate breakage.

6. **Every API endpoint must:**
   - Return real computed data (not stubs)
   - Handle errors with consistent JSON: `{"error": str, "detail": str, "status_code": int}`
   - Validate input (Pydantic models)
   - Support pagination where lists are returned (`?page=1&page_size=50`)
   - Include `org_id` tenant isolation
   - Log operations via structlog

7. **Every CLI command must:**
   - Call the same core functions as the API (NOT direct SQLite)
   - Support `--format json|table|csv` output
   - Return non-zero exit code on failure
   - Include `--help` with usage examples

8. **Competitive claims must be verifiable.** If we say "6,265 lines of reachability analysis," a prospect should be able to call `POST /api/v1/reachability/analyze` with a Python repo and get real call graphs back.

---

## Definition of Done

Stop when ALL of these are true:

- [ ] Every scanner grade is B+ or higher (currently 4 are below)
- [ ] Reachability analysis works for Python, JavaScript, and Java (not just Python)
- [ ] Code-to-cloud tracing has API endpoints and returns real data
- [ ] Material change detection is wired to brain pipeline and developer profiles
- [ ] CI/CD pipeline gate endpoint exists and returns binary pass/fail
- [ ] License compliance covers 50+ licenses with SPDX expression parsing
- [ ] CSPM has 100+ rules including live cloud API scanning capability
- [ ] Container scanning includes K8s manifest analysis
- [ ] SBOM includes transitive dependencies and VEX support
- [ ] Brain pipeline has false positive feedback loop with measurable FP rate
- [ ] All CLI commands call core functions (no direct SQLite, no stub data)
- [ ] All 13 orphaned API routers are either wired to UI/CLI or removed
- [ ] All buried core engines (causal inference, GNN, Monte Carlo, etc.) have API endpoints
- [ ] SIEM push integration exists (syslog or Splunk HEC)
- [ ] Full test suite passes (7,500+ tests, 0 failures)
- [ ] App starts cleanly with 1,029+ routes
- [ ] A demo comparing ALdeci vs Apiiro vs Aikido for each feature shows ALdeci matching or exceeding on 18/22 features

---

## Start Here

1. Run `python -m pytest tests/ --timeout=10 -x -q` to confirm baseline
2. Read `suite-evidence-risk/risk/reachability/proprietary_analyzer.py` — understand the reachability architecture
3. Read `suite-core/core/code_to_cloud_tracer.py` — understand what exists
4. Read `suite-core/core/material_change_detector.py` — audit depth
5. Start with Tier 1.1 (reachability JS/Java fix) — this is the #1 competitive gap vs Apiiro
6. Then Tier 2.1 (CI/CD gate endpoint) — this is the #1 competitive gap vs Aikido
7. Work through each tier systematically

**Remember: Apiiro raised $100M+ and Aikido raised $17M. Your job is to build a product that makes investors wonder why they need those companies when ALdeci exists. Every endpoint, every analysis, every report must demonstrate technical depth that justifies $100K+/year enterprise pricing.**
